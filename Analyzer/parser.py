import re
from datetime import datetime

def parse_line(line):
    # Extract hour from timestamp, e.g. "Mar 15 02:14:23" -> 2
    hour = None
    time_match = re.search(r"\w{3} \d+ (\d{2}):\d{2}:\d{2}", line)
    if time_match:
        hour = int(time_match.group(1))

    failed_match = re.search(r"Failed password for (\S+) from ([\d.]+)", line)
    if failed_match:
        return {
            "event_type": "failed_login",
            "user": failed_match.group(1),
            "ip": failed_match.group(2),
            "hour": hour,
            "raw_line": line.strip(),
        }

    accepted_match = re.search(r"Accepted password for (\S+) from ([\d.]+)", line)
    if accepted_match:
        return {
            "event_type": "successful_login",
            "user": accepted_match.group(1),
            "ip": accepted_match.group(2),
            "hour": hour,
            "raw_line": line.strip(),
        }

    sudo_match = re.search(r"(\w+) : TTY=.* COMMAND=", line)
    if sudo_match:
        return {
            "event_type": "sudo_command",
            "user": sudo_match.group(1),
            "hour": hour,
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
    events = parse_log_file("sample_logs/auth.log")
    for e in events:
        print(e)


