def generate_html_report(findings, output_path="report.html"):
    """Takes a list of finding dictionaries and writes an HTML report file."""
    
    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding['type']}</td>
            <td>{finding['ip']}</td>
            <td>{finding['severity']}</td>
            <td>{finding['detail']}</td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>Security Log Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #333; color: white; }}
            .high {{ color: darkorange; }}
            .critical {{ color: red; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>Security Log Analysis Report</h1>
        <p>Total findings: {len(findings)}</p>
        <table>
            <tr>
                <th>Type</th>
                <th>IP Address</th>
                <th>Severity</th>
                <th>Detail</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(output_path, "w") as f:
        f.write(html)

    print(f"Report written to {output_path}")


if __name__ == "__main__":
    from parser import parse_log_file
    from detectors import detect_brute_force, detect_breach_after_brute_force
    events = parse_log_file("sample_logs/auth.log")
    findings = detect_brute_force(events) + detect_breach_after_brute_force(events)
    generate_html_report(findings, "report.html")
    