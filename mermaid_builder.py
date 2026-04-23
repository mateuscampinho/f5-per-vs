import re


def _safe_id(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]', '_', str(text))


def _label(text: str) -> str:
    return str(text).replace('"', "'")


def _pool_label(pool_name: str, members: list) -> str:
    """Build a pool node label with members embedded inside the box."""
    header = f"<b>{_label(pool_name)}</b>"
    if not members:
        return header
    rows = []
    for m in members:
        addr  = m.get("address", m.get("name", ""))
        port  = m.get("port", "")
        state = (m.get("state") or "").lower()
        icon  = "&#9679;" if "up" in state else "&#9675;" if state else "&#183;"
        rows.append(f"{icon} {_label(addr)}:{port}")
    return header + "<br/>" + "<br/>".join(rows)


def build_diagram(vs_data: dict, pools: dict, policies: list, irules: list) -> tuple[str, dict]:
    """Returns (mermaid_diagram, detail_nodes)."""
    lines = ["flowchart TD"]
    detail_nodes: dict[str, dict] = {}

    # VS Root
    vs_name = vs_data.get("name", "VS")
    dest = vs_data.get("destination", "N/A")
    snat = vs_data.get("sourceAddressTranslation", {})
    snat_str = f"SNAT: {snat.get('type', 'none')}"
    if snat.get("pool"):
        snat_str += f" ({snat['pool']})"

    profiles_raw = vs_data.get("profiles", {})
    if isinstance(profiles_raw, dict):
        profile_items = [p for p in profiles_raw.get("items", []) if isinstance(p, dict)]
        profiles_str = ", ".join(p.get("name", "") for p in profile_items[:4]) or "N/A"
    else:
        profiles_str = "N/A"

    vs_id = _safe_id(vs_name)
    lines.append(
        f'  {vs_id}["<b>VS: {_label(vs_name)}</b><br/>Dest: {_label(dest)}<br/>'
        f'{_label(snat_str)}<br/>Profiles: {_label(profiles_str)}"]'
    )

    # Branch 1: Default Pool
    default_pool_path = vs_data.get("pool")
    if default_pool_path and default_pool_path in pools:
        pool = pools[default_pool_path]
        pool_id = _safe_id(f"pool_{pool.get('name', 'pool')}")
        lbl = _pool_label(pool.get("name", default_pool_path), pool.get("members_detail", []))
        lines.append(f'  {vs_id} -->|"Default Pool"| {pool_id}["{lbl}"]:::pool')

    # Branch 2: LTM Policies
    for policy_data in policies:
        pol_name = policy_data.get("name", "policy")
        pol_id = _safe_id(f"pol_{pol_name}")
        lines.append(f'  {vs_id} -->|"LTM Policy"| {pol_id}["{_label(pol_name)}"]:::policy')
        detail_nodes[pol_id] = {"type": "policy", "name": pol_name}

        for rule in _ref_items(policy_data, "rulesReference"):
            rule_name = rule.get("name", "rule")
            rule_id = _safe_id(f"rule_{pol_name}_{rule_name}")
            cond_items = _ref_items(rule, "conditionsReference")
            cond_str = "; ".join(_build_condition_label(c) for c in cond_items[:2]) or "no conditions"
            lines.append(f'  {pol_id} --> {rule_id}["Rule: {_label(rule_name)}<br/>If: {_label(cond_str)}"]')

            for action in _ref_items(rule, "actionsReference"):
                if action.get("forward") and action.get("pool"):
                    fwd_pool_path = action["pool"]
                    if fwd_pool_path in pools:
                        fwd_pool = pools[fwd_pool_path]
                        fwd_pool_id = _safe_id(f"fwdpool_{pol_name}_{rule_name}_{fwd_pool.get('name','p')}")
                        lbl = _pool_label(fwd_pool.get("name", fwd_pool_path), fwd_pool.get("members_detail", []))
                        lines.append(f'  {rule_id} -->|"forward"| {fwd_pool_id}["{lbl}"]:::pool')

    # Branch 3: iRules
    for irule_data in irules:
        rule_name = irule_data.get("name", "irule")
        irule_id = _safe_id(f"irule_{rule_name}")
        lines.append(f'  {vs_id} -->|"iRule"| {irule_id}["{_label(rule_name)}"]:::irule')
        detail_nodes[irule_id] = {"type": "irule", "name": rule_name}

        for pool_path, pool in irule_data.get("referenced_pools", {}).items():
            p_id = _safe_id(f"irulepool_{rule_name}_{pool.get('name','p')}")
            lbl = _pool_label(pool.get("name", pool_path), pool.get("members_detail", []))
            lines.append(f'  {irule_id} -->|"pool cmd"| {p_id}["{lbl}"]:::pool')

    lines.append("  classDef irule  fill:#ffe0b2,stroke:#e65100")
    lines.append("  classDef policy fill:#e3f2fd,stroke:#1565c0")
    lines.append("  classDef pool   fill:#f3f0ff,stroke:#6d28d9")
    return "\n".join(lines), detail_nodes


def _build_condition_label(cond: dict) -> str:
    op = "NOT " if cond.get("not") else ""
    if cond.get("startsWith"):  op += "startsWith"
    elif cond.get("endsWith"):  op += "endsWith"
    elif cond.get("contains"):  op += "contains"
    elif cond.get("equals"):    op += "equals"
    elif cond.get("matches"):   op += "matches"
    else:                       op += "is"

    if cond.get("httpUri"):
        subj = "URI.path" if cond.get("path") else "URI"
    elif cond.get("httpHeader"):
        subj = f"Header({cond.get('tmName','')})"
    elif cond.get("httpMethod"):
        subj = "Method"
    elif cond.get("address") and cond.get("tcp"):
        subj = "src-IP"
    elif cond.get("sslExtension"):
        subj = "SSL"
    else:
        subj = "match"

    if cond.get("datagroup"):
        val = f"datagroup:{cond['datagroup'].split('/')[-1]}"
    else:
        val = ", ".join(str(v) for v in cond.get("values", [])[:2])

    return f"{subj} {op} {val}".strip() if val else f"{subj} {op}".strip()


def _ref_items(obj: dict, key: str) -> list:
    ref = obj.get(key, {})
    return ref.get("items", []) if isinstance(ref, dict) else []
