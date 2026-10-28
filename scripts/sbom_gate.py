#!/usr/bin/env python3
"""PR security gate: diff SBOMs, diff vulnerability scans, fail on high CVSS.

Usage: sbom_gate.py base.xml pr.xml base-vulns.json pr-vulns.json
Env:   CVSS_THRESHOLD (default 7.5)   MODE=delta|full   ONLY_FIXABLE=true|false
"""
import json, os, sys
import xml.etree.ElementTree as ET

THRESHOLD = float(os.getenv("CVSS_THRESHOLD", "7.5"))
MODE = os.getenv("MODE", "delta")
ONLY_FIXABLE = os.getenv("ONLY_FIXABLE", "false").lower() == "true"
# Used only when a finding has no numeric CVSS score at all
FALLBACK = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1}


def local(tag):
    return tag.split("}")[-1]


def components(path):
    """{package identity: version} from a CycloneDX XML SBOM."""
    found = {}
    for el in ET.parse(path).getroot().iter():
        if local(el.tag) != "component":
            continue
        kids = {local(c.tag): (c.text or "").strip() for c in el}
        purl = kids.get("purl", "")
        ident = purl.split("?")[0].rsplit("@", 1)[0] if purl else kids.get("name", "")
        found[ident] = kids.get("version", "")
    return found


def findings(path):
    """{(vuln id, package, version): details} from a Grype JSON report."""
    out = {}
    for m in json.load(open(path)).get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        fix = v.get("fix") or {}
        if ONLY_FIXABLE and fix.get("state") != "fixed":
            continue
        scores = [
            float(c["metrics"]["baseScore"])
            for src in [v] + (m.get("relatedVulnerabilities") or [])
            for c in (src.get("cvss") or [])
            if (c.get("metrics") or {}).get("baseScore") is not None
        ]
        score = max(scores) if scores else FALLBACK.get((v.get("severity") or "").lower(), 0.0)
        out[(v["id"], a["name"], a["version"])] = {
            "id": v["id"], "pkg": a["name"], "ver": a["version"],
            "score": score, "sev": v.get("severity", "?"),
            "fix": ", ".join(fix.get("versions") or []) or "-",
        }
    return out


def table(rows, cols):
    if not rows:
        return "_none_\n"
    head = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
    return head + "".join("| " + " | ".join(str(r[c]) for c in cols) + " |\n" for r in rows[:40])


def main():
    base_x, pr_x, base_j, pr_j = sys.argv[1:5]
    bc, pc = components(base_x), components(pr_x)
    added = [{"package": k, "version": pc[k]} for k in sorted(pc.keys() - bc.keys())]
    removed = [{"package": k, "version": bc[k]} for k in sorted(bc.keys() - pc.keys())]
    changed = [{"package": k, "from": bc[k], "to": pc[k]}
               for k in sorted(bc.keys() & pc.keys()) if bc[k] != pc[k]]

    bf, pf = findings(base_j), findings(pr_j)
    new = {k: v for k, v in pf.items() if k not in bf}
    resolved = [k for k in bf if k not in pf]
    scope = new if MODE == "delta" else pf
    blockers = sorted((v for v in scope.values() if v["score"] > THRESHOLD),
                      key=lambda v: -v["score"])
    base_over = sum(1 for v in bf.values() if v["score"] > THRESHOLD)
    cols = ["id", "pkg", "ver", "score", "sev", "fix"]

    r = [
        f"## PR security gate: {'FAILED' if blockers else 'PASSED'}\n",
        f"Policy: block if CVSS > {THRESHOLD} | mode: `{MODE}`"
        f"{' | fixable only' if ONLY_FIXABLE else ''}\n",
        f"- Components: base {len(bc)}, PR {len(pc)} "
        f"(+{len(added)} added, -{len(removed)} removed, ~{len(changed)} changed)",
        f"- Findings: base {len(bf)} ({base_over} above threshold), PR {len(pf)}, "
        f"new in PR {len(new)}, resolved by PR {len(resolved)}\n",
    ]
    if blockers:
        r += [f"### Blocking findings (CVSS > {THRESHOLD})\n", table(blockers, cols)]
    r += ["### All new findings from this PR\n",
          table(sorted(new.values(), key=lambda v: -v["score"]), cols)]
    r += ["### Dependency changes\n",
          "**Added**\n", table(added, ["package", "version"]),
          "**Changed**\n", table(changed, ["package", "from", "to"]),
          "**Removed**\n", table(removed, ["package", "version"])]
    print("\n".join(r))
    sys.exit(1 if blockers else 0)


if __name__ == "__main__":
    main()
    