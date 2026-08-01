import argparse
from asyncio import events
from analyzer.parser import parse_log_file
from analyzer.detectors import (
    detect_brute_force,
    detect_breach_after_brute_force,
    detect_off_hours_login,
    detect_username_enumeration,
    detect_sudo_spike,
)
from analyzer.report import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH auth logs for suspicious activity."
    )
    parser.add_argument(
        "--log", required=True, help="Path to the auth.log file to analyze"
    )
    parser.add_argument(
        "--output", default="report.html", help="Path to write the HTML report"
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Number of failed attempts before flagging as brute force (default: 5)"
    )

    args = parser.parse_args()

    print(f"Parsing log file: {args.log}")
    events = parse_log_file(args.log)
    print(f"Found {len(events)} login-related events")

    sudo_events = [e for e in events if e["event_type"] == "sudo_command"]

    findings = (
        detect_brute_force(events, failure_threshold=args.threshold)
        + detect_breach_after_brute_force(events, failure_threshold=args.threshold)
        + detect_off_hours_login(events)
        + detect_username_enumeration(events)
        + detect_sudo_spike(sudo_events)
    )
    print(f"Found {len(findings)} suspicious findings")

    generate_html_report(findings, args.output)


if __name__ == "__main__":
    main()