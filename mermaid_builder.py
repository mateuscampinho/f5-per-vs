import re


def _safe_id(text: str) -> str:
    """Convert text to a safe Mermaid node ID."""
    return re.sub(r'[^a-zA-Z0-9_]', '_', str(text))


def _label(text: str) -> str:
    """Escape quotes in label text."""
    return str(text).replace('"', "'")


def build_diagram(vs_data: dict, pools: dict, policies: list, irules: list) -> str:
    lines = ["flowchart TD"]

    # --- VS Root Node ---
    vs_name = vs_data.get("name", "VS")
    dest = vs_data.get("destination", "N/A")
    snat = vs_data.get("sourceAddressTranslation", {})
    snat_str = f"SNAT: {snat.get('type','none')}"
    if snat.get("pool"):
        snat_str += f" ({snat['pool']})"

    profiles_raw = vs_data.get("profiles", {})
    if isinstance(profiles_raw, dict):
        profile_names = [p for p in profiles_raw.get("items", [{"name": "N/A"}]) if isinstance(p, dict)]
        profiles_str = ", ".join(p.get("name", "") for p in profile_names[:4])
    else:
        profiles_str = "N/A"

    vs_id = _safe_id(vs_name)
    lines.append(
        f'  {vs_id}["<b>VS: {_label(vs_name)}</b><br/>Dest: {_label(dest)}<br/>'
        f'{_label(snat_str)}<br/>Profiles: {_label(profiles_str)}"]'
    )

    # --- Branch 1: Default Pool ---
    default_pool_path = vs_data.get("pool")
    if default_pool_path and default_pool_path in pools:
        pool = pools[default_pool_path]
        pool_id = _safe_id(f"pool_{pool.get('name','pool')}")
        pool_name = pool.get("name", default_pool_path)
        lines.append(f'  {vs_id} -->|"Default Pool"| {pool_id}["{_label(pool_name)}"]')
        _append_members(lines, pool_id, pool.get("members_detail", []))

    # --- Branch 2: LTM Policies ---
    for policy_data in policies:
        pol_name = policy_data.get("name", "policy")
        pol_id = _safe_id(f"pol_{pol_name}")
        lines.append(f'  {vs_id} -->|"LTM Policy"| {pol_id}["{_label(pol_name)}"]')

        rules = policy_data.get("rules", {})
        rule_items = rules.get("items", []) if isinstance(rules, dict) else []

        for rule in rule_items:
            rule_name = rule.get("name", "rule")
            rule_id = _safe_id(f"rule_{pol_name}_{rule_name}")

            conditions = rule.get("conditions", {})
            cond_items = conditions.get("items", []) if isinstance(conditions, dict) else []
            cond_str = "; ".join(
                _build_condition_label(c) for c in cond_items[:2]
            ) or "no conditions"

            lines.append(f'  {pol_id} --> {rule_id}["Rule: {_label(rule_name)}<br/>If: {_label(cond_str)}"]')

            actions = rule.get("actions", {})
            action_items = actions.get("items", []) if isinstance(actions, dict) else []

            for action in action_items:
                if action.get("forward") and action.get("pool"):
                    fwd_pool_path = action["pool"]
                    if fwd_pool_path in pools:
                        fwd_pool = pools[fwd_pool_path]
                        fwd_pool_id = _safe_id(f"fwdpool_{pol_name}_{rule_name}_{fwd_pool.get('name','p')}")
                        lines.append(
                            f'  {rule_id} -->|"forward"| {fwd_pool_id}["{_label(fwd_pool.get("name", fwd_pool_path))}"]'
                        )
                        _append_members(lines, fwd_pool_id, fwd_pool.get("members_detail", []))

    # --- Branch 3: iRules ---
    for irule_data in irules:
        rule_name = irule_data.get("name", "irule")
        irule_id = _safe_id(f"irule_{rule_name}")
        lines.append(f'  {vs_id} -->|"iRule"| {irule_id}["{_label(rule_name)}"]:::irule')

        for pool_path, pool in irule_data.get("referenced_pools", {}).items():
            p_id = _safe_id(f"irulepool_{rule_name}_{pool.get('name','p')}")
            lines.append(
                f'  {irule_id} -->|"pool cmd"| {p_id}["{_label(pool.get("name", pool_path))}"]'
            )
            _append_members(lines, p_id, pool.get("members_detail", []))

    lines.append("  classDef irule fill:#ffe0b2,stroke:#e65100")
    return "\n".join(lines)


def _build_condition_label(cond: dict) -> str:
    parts = []
    for key in ("httpUri", "httpHeader", "httpMethod", "sslExtension"):
        if cond.get(key):
            parts.append(key)
    values = cond.get("values", [])
    val_str = ",".join(str(v) for v in values[:2])
    return f"{'/'.join(parts) or 'match'}: {val_str}" if val_str else "/".join(parts) or "condition"


def _append_members(lines: list, pool_id: str, members: list):
    for i, member in enumerate(members):
        m_name = member.get("name", f"member{i}")
        m_addr = member.get("address", "")
        m_port = member.get("port", "")
        m_state = member.get("state", "")
        m_id = _safe_id(f"{pool_id}_m{i}")
        label = f"{_label(m_name)}<br/>{_label(m_addr)}:{m_port}"
        if m_state:
            label += f"<br/>({_label(m_state)})"
        lines.append(f'  {pool_id} --> {m_id}["{label}"]:::member')

    if members:
        lines.append("  classDef member fill:#e8f5e9,stroke:#388e3c")
