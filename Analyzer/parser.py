import re

def parse_line(line):
    """Extracts structured data from one log line, or returns None if irrelevant."""
    
    # Pattern for failed login: "Failed password for <user> from <ip>"
    failed_match = re.search(r"Failed password for (\S+) from ([\d.]+)", line)
    if failed_match:
        return {
            "event_type": "failed_login",
            "user": failed_match.group(1),
            "ip": failed_match.group(2),
            "raw_line": line.strip(),
        }

    # Pattern for successful login
    accepted_match = re.search(r"Accepted password for (\S+) from ([\d.]+)", line)
    if accepted_match:
        return {
            "event_type": "successful_login",
            "user": accepted_match.group(1),
            "ip": accepted_match.group(2),
            "raw_line": line.strip(),
        }

    return None


def parse_log_file(filepath):
    """Reads a log file and returns a list of structured event dictionaries."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events
   
   
if __name__ == "__main__":
    with open("sample_logs/auth.log", "r") as f:
        lines = f.readlines()
    print(f"Read {len(lines)} lines from file")
    
    events = parse_log_file("sample_logs/auth.log")
    print(f"Found {len(events)} events")
    for e in events:
        print(e)