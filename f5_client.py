import re
import httpx


class F5Client:
    def __init__(self, host: str, username: str, password: str):
        self.base_url = f"https://{host}/mgmt/tm"
        self.auth = (username, password)
        self.client = httpx.AsyncClient(verify=False, timeout=30.0)

    async def close(self):
        await self.client.aclose()

    async def _get(self, path: str) -> dict:
        url = f"{self.base_url}{path}"
        resp = await self.client.get(url, auth=self.auth)
        resp.raise_for_status()
        return resp.json()

    async def list_vs_matches(self, query: str) -> list[dict]:
        """Return all VSes whose name or destination IP contains the query."""
        data = await self._get("/ltm/virtual?$select=name,destination,partition,pool")
        q = query.lower()
        return [
            vs for vs in data.get("items", [])
            if q in vs.get("name", "").lower() or q in vs.get("destination", "").lower()
        ]

    async def get_vs(self, partition: str, vs_name: str) -> dict:
        return await self._get(f"/ltm/virtual/~{partition}~{vs_name}")

    async def get_vs_waf_policy(self, partition: str, vs_name: str) -> str | None:
        """Return ASM policy name if WAF is enabled on this VS, else None."""
        full_path = f"/{partition}/{vs_name}"
        try:
            # Try filtered query first (URL-encode the slash)
            encoded = full_path.replace("/", "%2F")
            data = await self._get(f"/asm/policies?$filter=virtualServers+eq+{encoded}&$select=name,virtualServers")
            for item in data.get("items", []):
                vs_list = item.get("virtualServers", [])
                if not vs_list or any(full_path in str(v) for v in vs_list):
                    return item.get("name")
        except Exception:
            pass
        try:
            # Fallback: fetch all and match client-side (capped to avoid large responses)
            data = await self._get("/asm/policies?$select=name,virtualServers&$top=200")
            for item in data.get("items", []):
                for vs in item.get("virtualServers", []):
                    if isinstance(vs, str) and vs_name in vs:
                        return item.get("name")
                    if isinstance(vs, dict) and vs_name in vs.get("name", ""):
                        return item.get("name")
        except Exception:
            pass
        return None

    async def get_vs_policies(self, partition: str, vs_name: str) -> list[dict]:
        try:
            data = await self._get(f"/ltm/virtual/~{partition}~{vs_name}/policies")
            return data.get("items", [])
        except httpx.HTTPStatusError:
            return []

    async def get_pool(self, pool_path: str) -> dict:
        partition, name = self._parse_path(pool_path)
        pool = await self._get(f"/ltm/pool/~{partition}~{name}")
        members_data = await self._get(
            f"/ltm/pool/~{partition}~{name}/members?$select=name,address,port,state"
        )
        pool["members_detail"] = members_data.get("items", [])
        return pool

    async def get_policy(self, policy_path: str) -> dict:
        partition, name = self._parse_path(policy_path)
        return await self._get(f"/ltm/policy/~{partition}~{name}?expandSubcollections=true")

    async def get_irule(self, irule_path: str) -> dict:
        partition, name = self._parse_path(irule_path)
        return await self._get(f"/ltm/rule/~{partition}~{name}")

    def _parse_path(self, path: str) -> tuple[str, str]:
        clean = path.lstrip("/").replace("~", "/")
        parts = clean.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return "Common", parts[0]


def extract_pools_from_irule(irule_text: str) -> list[str]:
    return list(set(re.findall(r'\bpool\s+([\w\-\.\/~]+)', irule_text)))
