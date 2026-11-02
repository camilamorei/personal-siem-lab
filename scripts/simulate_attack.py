"""
Attack simulator for the Personal SIEM Lab.

Sends login attempts to the LOCAL app (127.0.0.1:5000) to generate events
for investigation in Splunk. For educational use only.

Each scenario binds to a different loopback IP (127.x.x.x), simulating
distinct sources without leaving the machine.
"""
import argparse
import http.client
import time
from urllib.parse import urlencode

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5000
USER_AGENT = "siem-lab-simulator/1.0"


def attempt_login(username, password, src_ip):
    """Send a login POST using src_ip as the source address."""
    conn = http.client.HTTPConnection(
        TARGET_HOST, TARGET_PORT, timeout=10, source_address=(src_ip, 0)
    )
    body = urlencode({"username": username, "password": password})
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT,
    }
    conn.request("POST", "/", body, headers)
    status = conn.getresponse().status
    conn.close()

    result = "success" if status == 200 else "failure"
    print(f"{src_ip:<12} {username:<14} {result}")
    return status


def normal_activity():
    """Legitimate use: valid logins and one typo."""
    attempt_login("alice", "Alice@2026", "127.0.0.10")
    attempt_login("bob", "Bob@2025", "127.0.0.11")  # wrong year
    attempt_login("bob", "Bob@2026", "127.0.0.11")


def brute_force():
    """Many passwords against ONE account from ONE IP. The last one is correct."""
    wordlist = [
        "123456", "password", "bob123", "qwerty", "admin", "letmein",
        "welcome", "senha123", "Bob@2024", "Bob@2025", "Bob@2026",
    ]
    for password in wordlist:
        attempt_login("bob", password, "127.0.0.66")
        time.sleep(0.2)


def password_spray():
    """ONE common password against MANY accounts, most of them nonexistent."""
    usernames = ["admin", "root", "test", "guest", "user", "administrator", "alice"]
    for username in usernames:
        attempt_login(username, "123456", "127.0.0.77")
        time.sleep(0.2)


SCENARIOS = {
    "normal": normal_activity,
    "bruteforce": brute_force,
    "spray": password_spray,
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attack simulator (127.0.0.1 only)")
    parser.add_argument("scenario", choices=[*SCENARIOS, "all"])
    args = parser.parse_args()

    if args.scenario == "all":
        for run in SCENARIOS.values():
            run()
    else:
        SCENARIOS[args.scenario]()
