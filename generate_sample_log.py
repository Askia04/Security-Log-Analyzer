import random
from datetime import datetime, timedelta

random_seed = 42
random.seed(random_seed)  # makes the "random" output the same every time we run it

NORMAL_USERS = ["alice", "bob", "carol", "dave"]
NORMAL_IPS = ["192.168.1.50", "192.168.1.51", "192.168.1.52", "192.168.1.53"]

lines = []
start_time = datetime(2026, 3, 15, 0, 0, 0)


def add_line(timestamp, process, pid, message):
    formatted = timestamp.strftime("%b %d %H:%M:%S")
    lines.append(f"{formatted} webserver {process}[{pid}]: {message}")


# --- Normal daytime traffic across many hours ---
current = start_time
pid = 10000
for _ in range(150):
    current += timedelta(minutes=random.randint(5, 45))
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    add_line(current, "sshd", pid, f"Accepted password for {user} from {ip} port {random.randint(50000,60000)} ssh2")
    pid += 1

    # occasional sudo command after a normal login
    if random.random() < 0.15:
        current += timedelta(minutes=random.randint(1, 10))
        add_line(current, "sudo", pid, f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/systemctl status nginx")
        pid += 1


# --- Attack 1: classic brute force that succeeds ---
attacker_1 = "185.220.101.5"
attack_time = start_time + timedelta(hours=2, minutes=14)
for i in range(9):
    add_line(attack_time, "sshd", pid, f"Failed password for root from {attacker_1} port {51100+i} ssh2")
    attack_time += timedelta(seconds=2)
    pid += 1
add_line(attack_time, "sshd", pid, f"Accepted password for root from {attacker_1} port 51110 ssh2")
pid += 1


# --- Attack 2: brute force that never succeeds (blocked/gave up) ---
attacker_2 = "91.203.5.12"
attack_time = start_time + timedelta(hours=3, minutes=47)
for i in range(7):
    add_line(attack_time, "sshd", pid, f"Failed password for admin from {attacker_2} port {44000+i} ssh2")
    attack_time += timedelta(seconds=3)
    pid += 1


# --- Attack 3: username enumeration (one IP trying many different users) ---
attacker_3 = "203.0.113.44"
attack_time = start_time + timedelta(hours=4, minutes=30)
enum_users = ["admin", "root", "test", "guest", "oracle", "postgres", "ubuntu"]
for user in enum_users:
    add_line(attack_time, "sshd", pid, f"Failed password for {user} from {attacker_3} port {45000+enum_users.index(user)} ssh2")
    attack_time += timedelta(seconds=4)
    pid += 1


# --- Attack 4: off-hours successful login (suspicious even without failures) ---
attack_time = start_time + timedelta(hours=3, minutes=15)  # 3:15 AM
add_line(attack_time, "sshd", pid, f"Accepted password for carol from 192.168.1.52 port 59234 ssh2")
pid += 1


# --- Sort everything chronologically, since we appended attacks out of order ---
def extract_time(line):
    return datetime.strptime(" ".join(line.split()[0:3]), "%b %d %H:%M:%S")

lines.sort(key=extract_time)

with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Generated {len(lines)} log lines to sample_logs/auth.log")