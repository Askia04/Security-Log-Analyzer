from analyzer.parser import parse_line

def test_parses_failed_login():
    line = "Mar 15 02:14:01 webserver sshd[12340]: Failed password for root from 185.220.101.5 port 51100 ssh2"
    result = parse_line(line)

    assert result is not None
    assert result["event_type"] == "failed_login"
    assert result["user"] == "root"
    assert result["ip"] == "185.220.101.5"


def test_parses_successful_login():
    line = "Mar 15 02:14:19 webserver sshd[12349]: Accepted password for root from 185.220.101.5 port 51109 ssh2"
    result = parse_line(line)

    assert result is not None
    assert result["event_type"] == "successful_login"
    assert result["user"] == "root"


def test_ignores_unrelated_lines():
    line = "Mar 15 14:40:00 webserver sudo[10006]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/systemctl restart nginx"
    result = parse_line(line)

    assert result is None