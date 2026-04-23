import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from f5_client import F5Client, extract_pools_from_irule
from mermaid_builder import build_diagram

# In-memory session store: session_id -> {host, username, password}
sessions: dict[str, dict] = {}

app = FastAPI(title="F5 VS Flow Mapper")
templates = Jinja2Templates(directory="templates")


# ---------- Models ----------

class LoginRequest(BaseModel):
    host: str
    username: str
    password: str


class SearchRequest(BaseModel):
    session_id: str
    query: str  # VS name or destination IP


# ---------- Routes ----------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/login")
async def login(req: LoginRequest, response: Response):
    # Test connectivity with credentials
    client = F5Client(req.host, req.username, req.password)
    try:
        await client._get("/ltm/virtual?$top=1&$select=name")
    except httpx.HTTPStatusError as e:
        await client.close()
        if e.response.status_code in (401, 403):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        raise HTTPException(status_code=502, detail=f"F5 error: {e.response.status_code}")
    except Exception as e:
        await client.close()
        raise HTTPException(status_code=502, detail=f"Cannot reach F5: {str(e)}")
    finally:
        await client.close()

    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "host": req.host,
        "username": req.username,
        "password": req.password,
    }
    return {"session_id": session_id, "message": "Login successful"}


@app.post("/api/logout")
async def logout(req: dict):
    sid = req.get("session_id", "")
    sessions.pop(sid, None)
    return {"message": "Logged out"}


@app.post("/api/search")
async def search(req: SearchRequest):
    sess = sessions.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")

    client = F5Client(sess["host"], sess["username"], sess["password"])
    try:
        return await _build_flow(client, req.query)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"F5 API error: {e.response.status_code} {e.response.text[:200]}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.close()


async def _build_flow(client: F5Client, query: str) -> dict:
    vs_data = await client.find_vs(query)

    pools: dict[str, dict] = {}  # path -> pool data
    policies_data: list[dict] = []
    irules_data: list[dict] = []

    # Default pool
    default_pool_path = vs_data.get("pool")
    if default_pool_path:
        pools[default_pool_path] = await client.get_pool(default_pool_path)

    # LTM Policies
    vs_policies = vs_data.get("policies", {})
    policy_items = vs_policies.get("items", []) if isinstance(vs_policies, dict) else []
    for p_ref in policy_items:
        pol_path = p_ref.get("fullPath") or p_ref.get("name", "")
        if not pol_path:
            continue
        try:
            pol_data = await client.get_policy(pol_path)
        except Exception:
            continue

        # Collect pools referenced by policy forward actions
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
            pool_key = pool_name if "/" in pool_name or "~" in pool_name else f"/Common/{pool_name}"
            if pool_key not in pools:
                try:
                    p = await client.get_pool(pool_key)
                    pools[pool_key] = p
                except Exception:
                    continue
            referenced_pools[pool_key] = pools[pool_key]

        irule["referenced_pools"] = referenced_pools
        irules_data.append(irule)

    diagram = build_diagram(vs_data, pools, policies_data, irules_data)

    return {
        "vs_name": vs_data.get("name"),
        "destination": vs_data.get("destination"),
        "mermaid": diagram,
        "summary": {
            "default_pool": default_pool_path,
            "policies": len(policies_data),
            "irules": len(irules_data),
            "total_pools": len(pools),
        },
    }
