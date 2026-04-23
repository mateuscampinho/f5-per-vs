import re


def _safe_id(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]', '_', str(text))


def _clean_addr(addr: str) -> str:
    return addr.split('%')[0]


def _node_size(label: str, char_w: float = 8.5, line_h: int = 22,
               pad_x: int = 40, pad_y: int = 30,
               min_w: int = 160, min_h: int = 56) -> tuple[int, int]:
    """Estimate Cytoscape node width/height from label text."""
    lines = label.split('\n')
    w = max(min_w, int(max(len(l) for l in lines) * char_w) + pad_x)
    h = max(min_h, len(lines) * line_h + pad_y)
    return w, h


def _pool_size(label: str) -> tuple[int, int]:
    return _node_size(label, char_w=8.0, line_h=20, pad_x=40, pad_y=28, min_w=180, min_h=60)


def _pool_label(pool_name: str, members: list) -> str:
    if not members:
        return pool_name
    sep = '─' * max(len(pool_name), 20)
    rows = [pool_name, sep]
    for m in members:
        addr     = _clean_addr(m.get('address', m.get('name', '')))
        port     = m.get('port', '')
        state    = (m.get('state') or '').lower()
        icon     = '▲' if 'up' in state else '▼' if state else '?'
        port_str = f':{port}' if port and str(port) != '0' else ''
        rows.append(f'{icon} {addr}{port_str}')
    return '\n'.join(rows)


def build_graph(vs_data: dict, pools: dict, policies: list,
                irules: list, waf_policy: str | None = None) -> tuple[dict, dict]:
    """Returns (graph, detail_nodes) for Cytoscape."""
    nodes: list[dict] = []
    edges: list[dict] = []
    detail_nodes: dict[str, dict] = {}
    seen_nodes: set[str] = set()

    def add_node(data: dict):
        nid = data['id']
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            nodes.append({'data': data})

    def add_edge(source: str, target: str, label: str = ''):
        edges.append({'data': {'source': source, 'target': target, 'label': label}})

    def sized(data: dict, label: str, is_pool: bool = False) -> dict:
        w, h = _pool_size(label) if is_pool else _node_size(label)
        return {**data, 'w': w, 'h': h}

    # ── VS root ──────────────────────────────────────────────────
    vs_name  = vs_data.get('name', 'VS')
    dest     = vs_data.get('destination', 'N/A')
    snat     = vs_data.get('sourceAddressTranslation', {})
    snat_str = f"SNAT: {snat.get('type', 'none')}"
    if snat.get('pool'):
        snat_str += f" ({snat['pool']})"

    profiles_raw = vs_data.get('profiles', {})
    if isinstance(profiles_raw, dict):
        p_items = [p for p in profiles_raw.get('items', []) if isinstance(p, dict)]
        profiles_str = ', '.join(p.get('name', '') for p in p_items[:4]) or 'N/A'
    else:
        profiles_str = 'N/A'

    vs_label = f'VS: {vs_name}\nDest: {dest}\n{snat_str}\nProfiles: {profiles_str}'
    vs_id    = _safe_id(vs_name)
    add_node(sized({'id': vs_id, 'label': vs_label, 'type': 'vs'}, vs_label))

    # ── WAF node ─────────────────────────────────────────────────
    if waf_policy:
        waf_id    = _safe_id(f'waf_{vs_name}')
        waf_label = f'WAF\n{waf_policy}'
        add_node(sized({'id': waf_id, 'label': waf_label, 'type': 'waf'}, waf_label))
        add_edge(vs_id, waf_id, 'WAF Policy')

    # ── Default Pool ─────────────────────────────────────────────
    default_pool_path = vs_data.get('pool')
    if default_pool_path and default_pool_path in pools:
        pool      = pools[default_pool_path]
        pool_id   = _safe_id(f"pool_{pool.get('name', 'pool')}")
        pool_lbl  = _pool_label(pool.get('name', default_pool_path), pool.get('members_detail', []))
        add_node(sized({'id': pool_id, 'label': pool_lbl, 'type': 'pool'}, pool_lbl, is_pool=True))
        add_edge(vs_id, pool_id, 'Default Pool')

    # ── LTM Policies ─────────────────────────────────────────────
    for policy_data in policies:
        pol_name  = policy_data.get('name', 'policy')
        pol_id    = _safe_id(f'pol_{pol_name}')
        controls  = policy_data.get('controls', [])
        # Mark ASM-only policies visually but keep them clickable
        pol_type  = 'policy_asm' if controls == ['asm'] else 'policy'
        pol_label = pol_name if pol_type == 'policy' else f'{pol_name}\n[ASM auto-policy]'

        add_node(sized({'id': pol_id, 'label': pol_label, 'type': pol_type}, pol_label))
        add_edge(vs_id, pol_id, 'LTM Policy')
        detail_nodes[pol_id] = {'type': 'policy', 'name': pol_name}

        for rule in _ref_items(policy_data, 'rulesReference'):
            rule_name  = rule.get('name', 'rule')
            rule_id    = _safe_id(f'rule_{pol_name}_{rule_name}')
            cond_items = _ref_items(rule, 'conditionsReference')
            cond_str   = '; '.join(_condition_label(c) for c in cond_items[:2]) or 'default'
            rule_label = f'Rule: {rule_name}\nIf: {cond_str}'

            add_node(sized({'id': rule_id, 'label': rule_label, 'type': 'rule'}, rule_label))
            add_edge(pol_id, rule_id)

            for action in _ref_items(rule, 'actionsReference'):
                if action.get('forward') and action.get('pool'):
                    fwd_path = action['pool']
                    if fwd_path in pools:
                        fwd_pool    = pools[fwd_path]
                        fwd_pool_id = _safe_id(f'fwdpool_{pol_name}_{rule_name}_{fwd_pool.get("name","p")}')
                        fwd_lbl     = _pool_label(fwd_pool.get('name', fwd_path), fwd_pool.get('members_detail', []))
                        add_node(sized({'id': fwd_pool_id, 'label': fwd_lbl, 'type': 'pool'}, fwd_lbl, is_pool=True))
                        add_edge(rule_id, fwd_pool_id, 'forward')

                if action.get('asm'):
                    pol_ref  = action.get('policy', '')
                    asm_name = pol_ref.split('/')[-1] if pol_ref else (waf_policy or 'ASM Policy')
                    asm_id   = _safe_id(f'asm_{rule_id}')
                    asm_lbl  = f'WAF\n{asm_name}'
                    add_node(sized({'id': asm_id, 'label': asm_lbl, 'type': 'waf'}, asm_lbl))
                    verb = 'ASM enable' if action.get('enable') else 'ASM disable' if action.get('disable') else 'ASM'
                    add_edge(rule_id, asm_id, verb)

                if action.get('redirect') and action.get('location'):
                    redir_id  = _safe_id(f'redir_{rule_id}')
                    redir_lbl = f'Redirect\n{action["location"][:50]}'
                    add_node(sized({'id': redir_id, 'label': redir_lbl, 'type': 'redirect'}, redir_lbl))
                    add_edge(rule_id, redir_id, 'redirect')

    # ── iRules ───────────────────────────────────────────────────
    for irule_data in irules:
        rule_name  = irule_data.get('name', 'irule')
        irule_id   = _safe_id(f'irule_{rule_name}')
        irule_lbl  = rule_name
        add_node(sized({'id': irule_id, 'label': irule_lbl, 'type': 'irule'}, irule_lbl))
        add_edge(vs_id, irule_id, 'iRule')
        detail_nodes[irule_id] = {'type': 'irule', 'name': rule_name}

        for pool_path, pool in irule_data.get('referenced_pools', {}).items():
            p_id  = _safe_id(f'irulepool_{rule_name}_{pool.get("name","p")}')
            p_lbl = _pool_label(pool.get('name', pool_path), pool.get('members_detail', []))
            add_node(sized({'id': p_id, 'label': p_lbl, 'type': 'pool'}, p_lbl, is_pool=True))
            add_edge(irule_id, p_id, 'pool cmd')

    return {'nodes': nodes, 'edges': edges}, detail_nodes


def _condition_label(cond: dict) -> str:
    op = 'NOT ' if cond.get('not') else ''
    if cond.get('startsWith'):  op += 'startsWith'
    elif cond.get('endsWith'):  op += 'endsWith'
    elif cond.get('contains'):  op += 'contains'
    elif cond.get('equals'):    op += 'equals'
    elif cond.get('matches'):   op += 'matches'
    else:                       op += 'is'

    if cond.get('httpUri'):       subj = 'URI.path' if cond.get('path') else 'URI'
    elif cond.get('httpHeader'):  subj = f"Header({cond.get('tmName','')})"
    elif cond.get('httpMethod'):  subj = 'Method'
    elif cond.get('address') and cond.get('tcp'): subj = 'src-IP'
    elif cond.get('sslExtension'): subj = 'SSL'
    else:                         subj = 'match'

    if cond.get('datagroup'):
        val = f"dg:{cond['datagroup'].split('/')[-1]}"
    else:
        val = ', '.join(str(v) for v in cond.get('values', [])[:2])

    return f'{subj} {op} {val}'.strip() if val else f'{subj} {op}'.strip()


def _ref_items(obj: dict, key: str) -> list:
    ref = obj.get(key, {})
    return ref.get('items', []) if isinstance(ref, dict) else []
