"""Regenerate Shadowrocket lists from public upstream domain rules."""
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
MUSE = "https://raw.githubusercontent.com/Lxp1986/rules-and-scripts/master/shadowrocket/muse/muse.list"
FACEBOOK = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Facebook/Facebook.list"
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

def main():
    upstream = parse(download(MUSE))
    facebook = parse(download(FACEBOOK), facebook=True)
    custom = parse((ROOT / "Muse-Custom.list").read_text(encoding="utf-8"))
    full = list(dict.fromkeys(upstream + custom))
    supplement = [rule for rule in full if not covered(rule, facebook)]
    (ROOT / "Muse.list").write_text(render("Muse", full), encoding="utf-8")
    (ROOT / "Muse-Supplement.list").write_text(render("Muse-Supplement", supplement), encoding="utf-8")
    print(f"Generated {len(full)} full and {len(supplement)} supplement rules.")

if __name__ == "__main__":
    main()
