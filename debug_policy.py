#!/usr/bin/env python3
"""
Run: python debug_policy.py <host> <user> <password> <vs_name> [partition]
Shows raw API response for VS policies to help debug rule parsing.
"""
import sys
import json
import httpx

def get(client, base, path):
    r = client.get(f"{base}{path}")
    r.raise_for_status()
    return r.json()

def main():
    if len(sys.argv) < 5:
        print("Usage: python debug_policy.py <host> <user> <password> <vs_name> [partition]")
        sys.exit(1)

    host, user, password, vs_name = sys.argv[1:5]
    partition = sys.argv[5] if len(sys.argv) > 5 else "Common"
    base = f"https://{host}/mgmt/tm"
    auth = (user, password)

    with httpx.Client(verify=False, timeout=30, auth=auth) as client:
        print(f"\n{'='*60}")
        print(f"VS: ~{partition}~{vs_name}")
        print('='*60)

        # 1. Full VS body
        vs = get(client, base, f"/ltm/virtual/~{partition}~{vs_name}")
        print("\n[1] VS 'policies' field (raw):")
        print(json.dumps(vs.get("policies", "NOT PRESENT"), indent=2))
        print("\n[1] VS 'rules' field (raw):")
        print(json.dumps(vs.get("rules", "NOT PRESENT"), indent=2))

        # 2. Policies subcollection
        print(f"\n[2] GET /ltm/virtual/~{partition}~{vs_name}/policies")
        try:
            pol_list = get(client, base, f"/ltm/virtual/~{partition}~{vs_name}/policies")
            print(json.dumps(pol_list, indent=2))
        except Exception as e:
            print(f"ERROR: {e}")
            pol_list = {}

        # 3. For each policy, fetch with expandSubcollections
        for item in pol_list.get("items", []):
            pol_path = item.get("fullPath") or item.get("name", "")
            clean = pol_path.lstrip("/").replace("~", "/").split("/")
            p, n = (clean[0], clean[1]) if len(clean) >= 2 else ("Common", clean[0])

            print(f"\n[3] GET /ltm/policy/~{p}~{n}?expandSubcollections=true")
            try:
                pol_full = get(client, base, f"/ltm/policy/~{p}~{n}?expandSubcollections=true")
                print(json.dumps(pol_full, indent=2))
            except Exception as e:
                print(f"ERROR: {e}")

            # Also try without expandSubcollections
            print(f"\n[4] GET /ltm/policy/~{p}~{n}/rules")
            try:
                rules = get(client, base, f"/ltm/policy/~{p}~{n}/rules?expandSubcollections=true")
                print(json.dumps(rules, indent=2))
            except Exception as e:
                print(f"ERROR: {e}")

if __name__ == "__main__":
    main()
