"""Compare two betterleaks JSON reports, ignoring Fingerprint differences."""

import json
import sys


COMPARE_FIELDS = [
    "RuleID", "Description", "File",
    "StartLine", "EndLine", "StartColumn", "EndColumn",
    "Match", "Secret", "Entropy",
    "Commit", "Author", "Email", "Date", "Message",
    "SymlinkFile",
]


def normalize_finding(f):
    """Create a comparable dict from a finding, excluding Fingerprint."""
    d = {field: f.get(field, "") for field in COMPARE_FIELDS}
    d["Entropy"] = f.get("Entropy", 0)
    d["Tags"] = tuple(sorted(f.get("Tags") or []))
    d["Attributes"] = tuple(sorted((f.get("Attributes") or {}).items()))
    return d


def finding_hash(f):
    """Fully hashable identity for a finding (includes commit metadata)."""
    n = normalize_finding(f)
    return tuple(n[k] for k in sorted(n))


def finding_key(f):
    """Grouping key (location-based, ignoring commit metadata)."""
    return (
        f.get("RuleID", ""),
        f.get("File", ""),
        f.get("StartLine", 0),
        f.get("EndLine", 0),
        f.get("StartColumn", 0),
        f.get("EndColumn", 0),
        f.get("Match", ""),
    )


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <report-main.json> <report-cel.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        main_findings = json.load(f)
    with open(sys.argv[2]) as f:
        cel_findings = json.load(f)

    print(f"Main findings:       {len(main_findings)}")
    print(f"CEL findings:        {len(cel_findings)}")
    print()

    # Index by key
    main_by_key = {}
    for f in main_findings:
        k = finding_key(f)
        main_by_key.setdefault(k, []).append(f)

    cel_by_key = {}
    for f in cel_findings:
        k = finding_key(f)
        cel_by_key.setdefault(k, []).append(f)

    all_keys = set(main_by_key) | set(cel_by_key)
    only_main = []
    only_cel = []
    field_diffs = []
    order_diffs = 0

    for k in sorted(all_keys):
        m_list = main_by_key.get(k, [])
        c_list = cel_by_key.get(k, [])

        if not m_list:
            only_cel.extend(c_list)
            continue
        if not c_list:
            only_main.extend(m_list)
            continue

        # Build multisets (hash -> count) for unordered comparison
        m_hashes = {}
        for f in m_list:
            h = finding_hash(f)
            m_hashes[h] = m_hashes.get(h, 0) + 1

        c_hashes = {}
        for f in c_list:
            h = finding_hash(f)
            c_hashes[h] = c_hashes.get(h, 0) + 1

        if m_hashes == c_hashes:
            # Same findings, possibly different order — not a real diff
            if len(m_list) > 1:
                m_order = [finding_hash(f) for f in m_list]
                c_order = [finding_hash(f) for f in c_list]
                if m_order != c_order:
                    order_diffs += 1
            continue

        # There are genuine differences — find unmatched findings
        all_h = set(m_hashes) | set(c_hashes)
        for h in all_h:
            mc = m_hashes.get(h, 0)
            cc = c_hashes.get(h, 0)
            if mc > cc:
                # Find a representative finding from main
                for f in m_list:
                    if finding_hash(f) == h:
                        only_main.append(f)
                        mc -= 1
                        if mc == cc:
                            break
            elif cc > mc:
                for f in c_list:
                    if finding_hash(f) == h:
                        only_cel.append(f)
                        cc -= 1
                        if cc == mc:
                            break

    # Report
    print(f"Only in main:        {len(only_main)}")
    print(f"Only in cel-filter:  {len(only_cel)}")
    print(f"Order-only diffs:    {order_diffs} (same findings, different order)")
    print()

    if only_main:
        print("=" * 60)
        print("FINDINGS ONLY IN MAIN (regressions)")
        print("=" * 60)
        for f in only_main:
            print(f"  [{f['RuleID']}] {f['File']}:{f.get('StartLine', '?')}")
            print(f"    Commit: {f.get('Commit', '')[:12]}")
            print(f"    Date:   {f.get('Date', '')}")
        print()

    if only_cel:
        print("=" * 60)
        print("FINDINGS ONLY IN CEL-FILTER (new)")
        print("=" * 60)
        for f in only_cel:
            print(f"  [{f['RuleID']}] {f['File']}:{f.get('StartLine', '?')}")
            print(f"    Commit: {f.get('Commit', '')[:12]}")
            print(f"    Date:   {f.get('Date', '')}")
        print()

    if not only_main and not only_cel:
        print("RESULT: Reports are equivalent (excluding Fingerprint)")
        sys.exit(0)
    else:
        print("RESULT: Reports differ")
        sys.exit(1)


if __name__ == "__main__":
    main()
