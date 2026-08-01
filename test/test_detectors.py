from analyzer.detectors import detect_brute_force, detect_breach_after_brute_force

def make_failed_event(ip):
    return {"event_type": "failed_login", "user": "root", "ip": ip, "raw_line": ""}

def make_success_event(ip):
    return {"event_type": "successful_login", "user": "root", "ip": ip, "raw_line": ""}


def test_detects_brute_force_above_threshold():
    events = [make_failed_event("1.2.3.4") for _ in range(6)]
    findings = detect_brute_force(events, failure_threshold=5)

    assert len(findings) == 1
    assert findings[0]["ip"] == "1.2.3.4"


def test_ignores_failures_below_threshold():
    events = [make_failed_event("1.2.3.4") for _ in range(3)]
    findings = detect_brute_force(events, failure_threshold=5)

    assert len(findings) == 0


def test_detects_breach_after_brute_force():
    events = [make_failed_event("1.2.3.4") for _ in range(6)] + [make_success_event("1.2.3.4")]
    findings = detect_breach_after_brute_force(events, failure_threshold=5)

    assert len(findings) == 1
    assert findings[0]["ip"] == "1.2.3.4"