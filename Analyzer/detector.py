from collections import defaultdict

def detect_brute_force(events, failure_threshold=5):
    """
    Flags any IP address with 'failure_threshold' or more failed 
    login attempts. Returns a list of findings.
    """
    failures_by_ip = defaultdict(list)

    # Group all failed_login events by their IP address
    for event in events:
        if event["event_type"] == "failed_login":
            failures_by_ip[event["ip"]].append(event)

    findings = []
    for ip, failed_attempts in failures_by_ip.items():
        if len(failed_attempts) >= failure_threshold:
            findings.append({
                "type": "brute_force",
                "ip": ip,
                "failure_count": len(failed_attempts),
                "severity": "high",
                "detail": f"{len(failed_attempts)} failed login attempts from {ip}",
            })

    return findings

def detect_breach_after_brute_force(events, failure_threshold=5):
    """
    Flags IPs that had many failed logins AND eventually succeeded —
    a strong signal of a successful attack, not just noise.
    """
    failures_by_ip = defaultdict(int)
    findings = []

    for event in events:
        ip = event["ip"]

        if event["event_type"] == "failed_login":
            failures_by_ip[ip] += 1

        elif event["event_type"] == "successful_login":
            prior_failures = failures_by_ip[ip]
            if prior_failures >= failure_threshold:
                findings.append({
                    "type": "breach_after_brute_force",
                    "ip": ip,
                    "user": event["user"],
                    "prior_failures": prior_failures,
                    "severity": "critical",
                    "detail": f"Login succeeded as '{event['user']}' from {ip} after {prior_failures} failed attempts",
                })

    return findings

if __name__ == "__main__":
    from parser import parse_log_file

    events = parse_log_file("sample_logs/auth.log")

    print("=== Brute Force Findings ===")
    for finding in detect_brute_force(events):
        print(finding)

    print("\n=== Breach After Brute Force Findings ===")
    for finding in detect_breach_after_brute_force(events):
        print(finding)