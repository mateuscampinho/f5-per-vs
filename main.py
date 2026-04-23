import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from f5_client import F5Client, extract_pools_from_irule
from graph_builder import build_graph

sessions: dict[str, dict] = {}

app = FastAPI(title="F5 VS Flow Mapper")
templates = Jinja2Templates(directory="templates")


class LoginRequest(BaseModel):
    host: str
    username: str
    password: str


class LogoutRequest(BaseModel):
    session_id: str


class SearchRequest(BaseModel):
    session_id: str
    query: str


class MapRequest(BaseModel):
    session_id: str
    partition: str
    vs_name: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/api/login")
async def login(req: LoginRequest):
    client = F5Client(req.host, req.username, req.password)
    try:
        await client._get("/ltm/virtual?$top=1&$select=name")
    except httpx.HTTPStatusError as e:
        if e.response.status_code in (401, 403):
            raise HTTPException(status_code=401, detail="Credenciais inválidas.")
        raise HTTPException(status_code=502, detail=f"Erro F5: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Não foi possível conectar: {e}")
    finally:
        await client.close()

    sid = str(uuid.uuid4())
    sessions[sid] = {"host": req.host, "username": req.username, "password": req.password}
    return {"session_id": sid}


@app.post("/api/logout")
async def logout(req: LogoutRequest):
    sessions.pop(req.session_id, None)
    return {"ok": True}


@app.post("/api/search")
async def search(req: SearchRequest):
    """Return a list of VSes matching the query (name or destination IP)."""
    sess = _get_session(req.session_id)
    client = F5Client(sess["host"], sess["username"], sess["password"])
    try:
        matches = await client.list_vs_matches(req.query)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"F5 API error {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.close()

    if not matches:
        raise HTTPException(status_code=404, detail=f"Nenhum VS encontrado para '{req.query}'")

    return {
        "matches": [
            {
                "name": vs.get("name"),
                "partition": vs.get("partition", "Common"),
                "destination": vs.get("destination", ""),
                "pool": vs.get("pool", ""),
            }
            for vs in matches
        ]
    }


@app.post("/api/map")
async def map_vs(req: MapRequest):
    """Build and return the full flow diagram for a specific VS."""
    sess = _get_session(req.session_id)
    client = F5Client(sess["host"], sess["username"], sess["password"])
    try:
        return await _build_flow(client, req.partition, req.vs_name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"F5 API error {e.response.status_code}: {e.response.text[:300]}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.close()


def _get_session(session_id: str) -> dict:
    sess = sessions.get(session_id)
    if not sess:
        raise HTTPException(status_code=401, detail="Sessão expirada. Faça login novamente.")
    return sess


async def _build_flow(client: F5Client, partition: str, vs_name: str) -> dict:
    vs_data = await client.get_vs(partition, vs_name)

    pools: dict[str, dict] = {}
    policies_data: list[dict] = []
    irules_data: list[dict] = []

    # Default pool
    default_pool_path = vs_data.get("pool")
    if default_pool_path:
        pools[default_pool_path] = await client.get_pool(default_pool_path)

    # LTM Policies via subcollection endpoint
    # Separate ASM auto-policies (controls=["asm"]) from real LTM policies
    waf_policy_from_ltm: str | None = None
    policy_refs = await client.get_vs_policies(partition, vs_name)
    for p_ref in policy_refs:
        pol_path = p_ref.get("fullPath") or p_ref.get("name", "")
        if not pol_path:
            continue
        try:
            pol_data = await client.get_policy(pol_path)
        except Exception:
            continue

        # If this policy exclusively controls ASM, treat it as WAF indicator
        controls = pol_data.get("controls", [])
        if controls == ["asm"]:
            waf_policy_from_ltm = pol_data.get("name", pol_path.split("/")[-1])
            continue  # don't render as LTM policy branch

        rule_items = _get_ref_items(pol_data, "rulesReference")
        for rule in rule_items:
            for action in _get_ref_items(rule, "actionsReference"):
                if action.get("forward") and action.get("pool"):
                    pool_path = action["pool"]
                    if pool_path not in pools:
                        try:
                            pools[pool_path] = await client.get_pool(pool_path)
                        except Exception:
                            pass

        policies_data.append(pol_data)

    # iRules
    vs_rules = vs_data.get("rules", [])
    if isinstance(vs_rules, str):
        vs_rules = [vs_rules]

    for rule_ref in vs_rules:
        rule_path = rule_ref if isinstance(rule_ref, str) else rule_ref.get("fullPath", "")
        if not rule_path:
            continue
        try:
            irule = await client.get_irule(rule_path)
        except Exception:
            continue

        irule_text = irule.get("apiAnonymous", "")
        referenced_pools: dict[str, dict] = {}
        for pool_name in extract_pools_from_irule(irule_text):
            pool_key = pool_name if ("/" in pool_name or "~" in pool_name) else f"/Common/{pool_name}"
            if pool_key not in pools:
                try:
                    pools[pool_key] = await client.get_pool(pool_key)
                except Exception:
                    continue
            referenced_pools[pool_key] = pools[pool_key]

        irule["referenced_pools"] = referenced_pools
        irules_data.append(irule)

    # WAF / ASM detection — try ASM API first, fall back to LTM policy detection
    waf_policy = await client.get_vs_waf_policy(partition, vs_name) or waf_policy_from_ltm

    graph, detail_nodes = build_graph(vs_data, pools, policies_data, irules_data, waf_policy)

    # Build detail store for frontend panel
    policy_map = {p.get("name"): p for p in policies_data}
    irule_map  = {r.get("name"): r for r in irules_data}
    detail_store: dict[str, dict] = {}

    for node_id, info in detail_nodes.items():
        if info["type"] == "policy":
            pol = policy_map.get(info["name"], {})
            detail_store[node_id] = {
                "type": "policy",
                "name": info["name"],
                "rules": [_serialize_rule(r) for r in _get_ref_items(pol, "rulesReference")],
            }
        elif info["type"] == "irule":
            irule = irule_map.get(info["name"], {})
            detail_store[node_id] = {
                "type": "irule",
                "name": info["name"],
                "content": irule.get("apiAnonymous", ""),
            }

    return {
        "vs_name": vs_name,
        "destination": vs_data.get("destination"),
        "graph": graph,
        "detail_store": detail_store,
        "summary": {
            "default_pool": default_pool_path,
            "policies": len(policies_data),
            "irules": len(irules_data),
            "total_pools": len(pools),
            "waf": waf_policy,
        },
    }


def _serialize_rule(rule: dict) -> dict:
    return {
        "name": rule.get("name", ""),
        "ordinal": rule.get("ordinal", 0),
        "conditions": _get_ref_items(rule, "conditionsReference"),
        "actions": _get_ref_items(rule, "actionsReference"),
    }


def _get_ref_items(obj: dict, key: str) -> list:
    """Extract items from a *Reference subcollection field."""
    ref = obj.get(key, {})
    if isinstance(ref, dict):
        return ref.get("items", [])
    return []
