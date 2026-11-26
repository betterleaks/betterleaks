import gc

import betterleaks_sdk

GH_PREFIX = "gh" + "p_"


def test_stress_gc():
    """Verify that repeated scans and garbage collection do not crash or leak memory."""
    for i in range(200):
        findings = betterleaks_sdk.scan_string(
            f"token_{i} = '{GH_PREFIX}{i}B3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5'"
        )
        assert len(findings) >= 1
        assert any(f.rule_id == "github-pat" for f in findings)
        del findings
        if i % 25 == 0:
            gc.collect()
