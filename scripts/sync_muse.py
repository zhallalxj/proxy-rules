"""Regenerate Shadowrocket lists from public upstream domain rules."""
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
MUSE = "https://raw.githubusercontent.com/Lxp1986/rules-and-scripts/master/shadowrocket/muse/muse.list"
FACEBOOK = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Facebook/Facebook.list"
META = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/meta.yaml"
KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}

def download(url):
    with urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8-sig")

def parse(text, *, facebook=False):
    result = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        fields = [p.strip() for p in line.split(",")]
        if facebook and fields[0] in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
            continue
        if len(fields) != 2 or fields[0] not in KINDS or not fields[1] or any(c.isspace() for c in fields[1]):
            raise ValueError(f"Unexpected rule: {line!r}")
        result.append((fields[0], fields[1].lower()))
    if not result:
        raise ValueError("Empty rule source")
    return result

def covered(rule, facebook_rules):
    kind, domain = rule
    for other_kind, value in facebook_rules:
        if other_kind == "DOMAIN-SUFFIX" and kind != "DOMAIN-KEYWORD" and (domain == value or domain.endswith("." + value)):
            return True
        if other_kind == "DOMAIN" and kind == "DOMAIN" and domain == value:
            return True
        if other_kind == "DOMAIN-KEYWORD" and value in domain:
            return True
    return False

def render(name, rules):
    return (
        f"# NAME: {name}\n"
        "# GENERATED: scripts/sync_muse.py; edit Muse-Custom.list instead\n"
        "# Upstream: https://github.com/Lxp1986/rules-and-scripts/blob/master/shadowrocket/muse/muse.list\n"
        "# Facebook coverage: https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/Facebook/Facebook.list\n"
        f"# TOTAL: {len(rules)}\n"
        + "".join(f"{kind},{domain}\n" for kind, domain in rules)
    )

def parse_meta_yaml(text):
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line == "payload:":
            continue
        if not line.startswith("- "):
            raise ValueError(f"Unexpected Meta YAML: {line!r}")
        rows.append(line[2:])
    return parse("\n".join(rows))

def facebook_all(text):
    # Validate domains and preserve all original IP/ASN rules and modifiers.
    parse(text, facebook=True)
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith(("#", "//", ";"))]

def render_meta(rules):
    return "# NAME: Meta\n# GENERATED: scripts/sync_muse.py; edit Muse-Custom.list for local additions\n# Facebook: https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/Facebook/Facebook.list\n# Muse: https://github.com/Lxp1986/rules-and-scripts/blob/master/shadowrocket/muse/muse.list\n# Meta: https://github.com/MetaCubeX/meta-rules-dat/blob/meta/geo/geosite/classical/meta.yaml\n# TOTAL: " + str(len(rules)) + "\n" + "\n".join(rules) + "\n"

def main():
    upstream = parse(download(MUSE))
    facebook_source = download(FACEBOOK)
    facebook = parse(facebook_source, facebook=True)
    meta = parse_meta_yaml(download(META))
    custom = parse((ROOT / "Muse-Custom.list").read_text(encoding="utf-8"))
    full = list(dict.fromkeys(upstream + custom))
    supplement = [rule for rule in full if not covered(rule, facebook)]
    (ROOT / "Muse.list").write_text(render("Muse", full), encoding="utf-8")
    (ROOT / "Muse-Supplement.list").write_text(render("Muse-Supplement", supplement), encoding="utf-8")
    combined = list(dict.fromkeys(facebook_all(facebook_source) + [f"{kind},{domain}" for kind, domain in full + meta]))
    (ROOT / "Meta.list").write_text(render_meta(combined), encoding="utf-8")
    print(f"Generated {len(combined)} combined Meta rules.")
    print(f"Generated {len(full)} full and {len(supplement)} supplement rules.")

if __name__ == "__main__":
    main()
