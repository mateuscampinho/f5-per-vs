import re


def _safe_id(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]', '_', str(text))


def _clean_addr(addr: str) -> str:
    """Strip F5 route-domain suffix (e.g. 10.0.0.1%1 -> 10.0.0.1)."""
    return addr.split('%')[0]


def _pool_label(pool_name: str, members: list) -> str:
    if not members:
        return pool_name
    rows = [pool_name, '─' * max(len(pool_name), 18)]
    for m in members:
        addr  = _clean_addr(m.get('address', m.get('name', '')))
        port  = m.get('port', '')
        state = (m.get('state') or '').lower()
        icon  = '▲' if 'up' in state else '▼' if state else '?'
        port_str = f':{port}' if port and str(port) != '0' else ''
        rows.append(f'{icon} {addr}{port_str}')
    return '\n'.join(rows)


def build_graph(vs_data: dict, pools: dict, policies: list,
                irules: list, waf_policy: str | None = None) -> tuple[dict, dict]:
    """
    Returns (graph, detail_nodes).
    graph: {nodes: [...], edges: [...]} for Cytoscape.
    detail_nodes: {node_id: {"type": "policy"|"irule", "name": str}}
    """
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

    # ── VS root ──────────────────────────────────────────
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

    vs_id = _safe_id(vs_name)
    add_node({
        'id': vs_id,
        'label': f'VS: {vs_name}\nDest: {dest}\n{snat_str}\nProfiles: {profiles_str}',
        'type': 'vs',
    })

    # ── WAF / ASM (VS-level) ─────────────────────────────
    if waf_policy:
        waf_id = _safe_id(f'waf_{vs_name}')
        add_node({'id': waf_id, 'label': f'WAF\n{waf_policy}', 'type': 'waf'})
        add_edge(vs_id, waf_id, 'WAF Policy')

    # ── Default Pool ─────────────────────────────────────
    default_pool_path = vs_data.get('pool')
    if default_pool_path and default_pool_path in pools:
        pool    = pools[default_pool_path]
        pool_id = _safe_id(f"pool_{pool.get('name', 'pool')}")
        add_node({
            'id': pool_id,
            'label': _pool_label(pool.get('name', default_pool_path), pool.get('members_detail', [])),
            'type': 'pool',
        })
        add_edge(vs_id, pool_id, 'Default Pool')

    # ── LTM Policies ─────────────────────────────────────
    for policy_data in policies:
        pol_name = policy_data.get('name', 'policy')
        pol_id   = _safe_id(f'pol_{pol_name}')
        add_node({'id': pol_id, 'label': pol_name, 'type': 'policy'})
        add_edge(vs_id, pol_id, 'LTM Policy')
        detail_nodes[pol_id] = {'type': 'policy', 'name': pol_name}

        for rule in _ref_items(policy_data, 'rulesReference'):
            rule_name = rule.get('name', 'rule')
            rule_id   = _safe_id(f'rule_{pol_name}_{rule_name}')

            cond_items = _ref_items(rule, 'conditionsReference')
            cond_str   = '; '.join(_condition_label(c) for c in cond_items[:2]) or 'default'

            add_node({'id': rule_id, 'label': f'Rule: {rule_name}\nIf: {cond_str}', 'type': 'rule'})
            add_edge(pol_id, rule_id)

            for action in _ref_items(rule, 'actionsReference'):
                # Forward to pool
                if action.get('forward') and action.get('pool'):
                    fwd_path = action['pool']
                    if fwd_path in pools:
                        fwd_pool    = pools[fwd_path]
                        fwd_pool_id = _safe_id(f'fwdpool_{pol_name}_{rule_name}_{fwd_pool.get("name","p")}')
                        add_node({
                            'id': fwd_pool_id,
                            'label': _pool_label(fwd_pool.get('name', fwd_path), fwd_pool.get('members_detail', [])),
                            'type': 'pool',
                        })
                        add_edge(rule_id, fwd_pool_id, 'forward')

                # ASM / WAF enforce action
                if action.get('asm'):
                    pol_ref  = action.get('policy', '')
                    asm_name = pol_ref.split('/')[-1] if pol_ref else 'ASM Policy'
                    asm_id   = _safe_id(f'asm_{rule_id}')
                    add_node({'id': asm_id, 'label': f'WAF\n{asm_name}', 'type': 'waf'})
                    add_edge(rule_id, asm_id, 'ASM enforce')

                # Redirect
                if action.get('redirect') and action.get('location'):
                    redir_id = _safe_id(f'redir_{rule_id}')
                    loc = action['location'][:50]
                    add_node({'id': redir_id, 'label': f'Redirect\n{loc}', 'type': 'redirect'})
                    add_edge(rule_id, redir_id, 'redirect')

    # ── iRules ───────────────────────────────────────────
    for irule_data in irules:
        rule_name = irule_data.get('name', 'irule')
        irule_id  = _safe_id(f'irule_{rule_name}')
        add_node({'id': irule_id, 'label': rule_name, 'type': 'irule'})
        add_edge(vs_id, irule_id, 'iRule')
        detail_nodes[irule_id] = {'type': 'irule', 'name': rule_name}

        for pool_path, pool in irule_data.get('referenced_pools', {}).items():
            p_id = _safe_id(f'irulepool_{rule_name}_{pool.get("name","p")}')
            add_node({
                'id': p_id,
                'label': _pool_label(pool.get('name', pool_path), pool.get('members_detail', [])),
                'type': 'pool',
            })
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

    if cond.get('httpUri'):
        subj = 'URI.path' if cond.get('path') else 'URI'
    elif cond.get('httpHeader'):
        subj = f"Header({cond.get('tmName','')})"
    elif cond.get('httpMethod'):
        subj = 'Method'
    elif cond.get('address') and cond.get('tcp'):
        subj = 'src-IP'
    elif cond.get('sslExtension'):
        subj = 'SSL'
    else:
        subj = 'match'

    if cond.get('datagroup'):
        val = f"dg:{cond['datagroup'].split('/')[-1]}"
    else:
        val = ', '.join(str(v) for v in cond.get('values', [])[:2])

    return f'{subj} {op} {val}'.strip() if val else f'{subj} {op}'.strip()


def _ref_items(obj: dict, key: str) -> list:
    ref = obj.get(key, {})
    return ref.get('items', []) if isinstance(ref, dict) else []
