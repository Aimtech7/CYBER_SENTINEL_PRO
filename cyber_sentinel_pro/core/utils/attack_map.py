ATTACK_MAP = {
    'sql_injection': 'T1190',
    'xss_reflected': 'T1059',
    'dir_found': 'T1046',
    'http_error': 'T1190',
    'auth_failure': 'T1110',
}


def map_finding(ftype: str) -> str:
    return ATTACK_MAP.get(ftype, '')


def enrich_findings(findings):
    out = []
    for f in findings:
        t = f.get('type')
        tech = map_finding(t)
        f2 = dict(f)
        if tech:
            f2['mitre_technique'] = tech
        out.append(f2)
    return out

