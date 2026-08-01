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
        if event["event_type"] not in ("failed_login", "successful_login"):
            continue
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


from datetime import datetime

def detect_off_hours_login(events, start_hour=0, end_hour=5):
    """Flags successful logins that happen during unusual hours (default: midnight-5am)."""
    findings = []
    for event in events:
        if event["event_type"] == "successful_login" and "hour" in event:
            if start_hour <= event["hour"] < end_hour:
                findings.append({
                    "type": "off_hours_login",
                    "ip": event["ip"],
                    "user": event["user"],
                    "severity": "medium",
                    "detail": f"Login as '{event['user']}' from {event['ip']} at {event['hour']}:00 (outside normal hours)",
                })
    return findings


def detect_username_enumeration(events, unique_user_threshold=4):
    """Flags an IP that tried logging in as many DIFFERENT usernames — 
    suggests the attacker is guessing valid accounts, not just one password."""
    users_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "failed_login":
            users_by_ip[event["ip"]].add(event["user"])

    findings = []
    for ip, users in users_by_ip.items():
        if len(users) >= unique_user_threshold:
            findings.append({
                "type": "username_enumeration",
                "ip": ip,
                "severity": "high",
                "detail": f"{ip} attempted {len(users)} different usernames: {', '.join(sorted(users))}",
            })
    return findings


def detect_sudo_spike(sudo_events, count_threshold=5):
    """Flags a user issuing an unusually high number of sudo commands."""
    sudo_by_user = defaultdict(int)
    for event in sudo_events:
        sudo_by_user[event["user"]] += 1

    findings = []
    for user, count in sudo_by_user.items():
        if count >= count_threshold:
            findings.append({
                "type": "sudo_spike",
                "user": user,
                "severity": "medium",
                "detail": f"User '{user}' issued {count} sudo commands",
            })
    return findings