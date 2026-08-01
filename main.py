import argparse
from analyzer.parser import parse_log_file
from analyzer.detectors import detect_brute_force, detect_breach_after_brute_force
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

    findings = (
        detect_brute_force(events, failure_threshold=args.threshold)
        + detect_breach_after_brute_force(events, failure_threshold=args.threshold)
    )
    print(f"Found {len(findings)} suspicious findings")

    generate_html_report(findings, args.output)


if __name__ == "__main__":
    main()