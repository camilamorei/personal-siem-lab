"""
Simulador de ataques do Personal SIEM Lab.

Faz tentativas de login contra a aplicação LOCAL (127.0.0.1:5000) para gerar
eventos que serão investigados no Splunk. Uso exclusivamente educacional.

Cada cenário "sai" por um IP de loopback diferente (127.x.x.x), simulando
origens distintas sem sair do próprio computador.
"""
import argparse
import http.client
import time
from urllib.parse import urlencode

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5000
USER_AGENT = "siem-lab-simulator/1.0"


def attempt_login(username, password, src_ip):
    """Envia um POST de login usando src_ip como IP de origem."""
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
    """Uso legítimo: logins certos e um erro de digitação."""
    attempt_login("alice", "Alice@2026", "127.0.0.10")
    attempt_login("bob", "Bob@2025", "127.0.0.11")  # errou o ano
    attempt_login("bob", "Bob@2026", "127.0.0.11")


def brute_force():
    """Muitas senhas contra UMA conta, de UM IP. A última está certa."""
    wordlist = [
        "123456", "password", "bob123", "qwerty", "admin", "letmein",
        "welcome", "senha123", "Bob@2024", "Bob@2025", "Bob@2026",
    ]
    for password in wordlist:
        attempt_login("bob", password, "127.0.0.66")
        time.sleep(0.2)


def password_spray():
    """UMA senha comum contra MUITAS contas, a maioria inexistente."""
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
    parser = argparse.ArgumentParser(description="Simulador de ataques (somente 127.0.0.1)")
    parser.add_argument("scenario", choices=[*SCENARIOS, "all"])
    args = parser.parse_args()

    if args.scenario == "all":
        for run in SCENARIOS.values():
            run()
    else:
        SCENARIOS[args.scenario]()
