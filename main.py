import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from f5_client import F5Client, extract_pools_from_irule
from mermaid_builder import build_diagram

sessions: dict[str, dict] = {}

app = FastAPI(title="F5 VS Flow Mapper")
templates = Jinja2Templates(directory="templates")


class LoginRequest(BaseModel):
    host: str
    username: str
    password: str


class SearchRequest(BaseModel):
    session_id: str
    query: str


class LogoutRequest(BaseModel):
    session_id: str


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
        raise HTTPException(status_code=502, detail=f"Não foi possível conectar ao F5: {e}")
    finally:
        await client.close()

    session_id = str(uuid.uuid4())
    sessions[session_id] = {"host": req.host, "username": req.username, "password": req.password}
    return {"session_id": session_id}


@app.post("/api/logout")
async def logout(req: LogoutRequest):
    sessions.pop(req.session_id, None)
    return {"ok": True}


@app.post("/api/search")
async def search(req: SearchRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=401, detail="Sessão expirada. Faça login novamente.")

    client = F5Client(sess["host"], sess["username"], sess["password"])
    try:
        return await _build_flow(client, req.query)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"F5 API error {e.response.status_code}: {e.response.text[:300]}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.close()


async def _build_flow(client: F5Client, query: str) -> dict:
    vs_data = await client.find_vs(query)
    partition = vs_data.get("partition", "Common")
    vs_name = vs_data.get("name", "")

    pools: dict[str, dict] = {}
    policies_data: list[dict] = []
    irules_data: list[dict] = []

    # Default pool
    default_pool_path = vs_data.get("pool")
    if default_pool_path:
        pools[default_pool_path] = await client.get_pool(default_pool_path)

    # LTM Policies — fetch via VS subcollection (the VS body only has a link, not items)
    policy_refs = await client.get_vs_policies(partition, vs_name)
    for p_ref in policy_refs:
        pol_path = p_ref.get("fullPath") or p_ref.get("name", "")
        if not pol_path:
            continue
        try:
            pol_data = await client.get_policy(pol_path)
        except Exception:
            continue

        rules = pol_data.get("rules", {})
        rule_items = rules.get("items", []) if isinstance(rules, dict) else []
        for rule in rule_items:
            actions = rule.get("actions", {})
            action_items = actions.get("items", []) if isinstance(actions, dict) else []
            for action in action_items:
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

    diagram, detail_nodes = build_diagram(vs_data, pools, policies_data, irules_data)

    # Build detail store for frontend clicks
    policy_map = {p.get("name"): p for p in policies_data}
    irule_map = {r.get("name"): r for r in irules_data}

    detail_store: dict[str, dict] = {}
    for node_id, info in detail_nodes.items():
        if info["type"] == "policy":
            pol = policy_map.get(info["name"], {})
            rules = pol.get("rules", {})
            rule_items = rules.get("items", []) if isinstance(rules, dict) else []
            detail_store[node_id] = {
                "type": "policy",
                "name": info["name"],
                "rules": [_serialize_rule(r) for r in rule_items],
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
        "mermaid": diagram,
        "detail_store": detail_store,
        "summary": {
            "default_pool": default_pool_path,
            "policies": len(policies_data),
            "irules": len(irules_data),
            "total_pools": len(pools),
        },
    }


def _serialize_rule(rule: dict) -> dict:
    conditions = rule.get("conditions", {})
    cond_items = conditions.get("items", []) if isinstance(conditions, dict) else []
    actions = rule.get("actions", {})
    action_items = actions.get("items", []) if isinstance(actions, dict) else []
    return {
        "name": rule.get("name", ""),
        "ordinal": rule.get("ordinal", 0),
        "conditions": cond_items,
        "actions": action_items,
    }
