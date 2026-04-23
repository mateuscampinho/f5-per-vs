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
