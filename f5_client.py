import re
import httpx
from typing import Optional


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

    async def find_vs(self, name_or_ip: str) -> dict:
        """Find a VS by name or destination IP."""
        data = await self._get("/ltm/virtual?$select=name,destination,pool,sourceAddressTranslation,profiles,rules,policies,partition")
        items = data.get("items", [])

        for vs in items:
            dest = vs.get("destination", "")
            vs_name = vs.get("name", "")
            if name_or_ip in vs_name or name_or_ip in dest:
                full = await self._get(f"/ltm/virtual/~{vs.get('partition','Common')}~{vs_name}")
                return full

        raise ValueError(f"Virtual Server '{name_or_ip}' not found")

    async def get_pool(self, pool_path: str) -> dict:
        """Fetch pool and its members."""
        partition, name = self._parse_path(pool_path)
        pool = await self._get(f"/ltm/pool/~{partition}~{name}")
        members_data = await self._get(f"/ltm/pool/~{partition}~{name}/members?$select=name,address,port,state")
        pool["members_detail"] = members_data.get("items", [])
        return pool

    async def get_policy(self, policy_path: str) -> dict:
        """Fetch LTM policy with rules."""
        partition, name = self._parse_path(policy_path)
        return await self._get(f"/ltm/policy/~{partition}~{name}?$expand=rules")

    async def get_irule(self, irule_path: str) -> dict:
        """Fetch iRule content."""
        partition, name = self._parse_path(irule_path)
        return await self._get(f"/ltm/rule/~{partition}~{name}")

    def _parse_path(self, path: str) -> tuple[str, str]:
        """Parse /Common/name or ~Common~name into (partition, name)."""
        clean = path.lstrip("/").replace("~", "/")
        parts = clean.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return "Common", parts[0]


def extract_pools_from_irule(irule_text: str) -> list[str]:
    """Find pool names referenced in iRule via 'pool <name>' command."""
    pattern = r'\bpool\s+([\w\-\.\/~]+)'
    return list(set(re.findall(pattern, irule_text)))
