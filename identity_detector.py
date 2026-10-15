
import csv
from collections import Counter, defaultdict

LOG_FILE = "login_logs.csv"
FAILED_LOGIN_THRESHOLD = 3

failed_attempts = Counter()
failed_by_ip = Counter()
user_ips = defaultdict(set)

try:
    with open(LOG_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "username", "status", "ip_address", "timestamp"
        }

        if not required_columns.issubset(set(reader.fieldnames or [])):
            raise ValueError(
                "CSV must contain username, status, "
                "ip_address and timestamp columns."
            )

        for row in reader:
            username = row["username"].strip()
            status = row["status"].strip().lower()
            ip_address = row["ip_address"].strip()
            timestamp = row["timestamp"].strip()

            if status == "failed":
                failed_attempts[username] += 1
                failed_by_ip[ip_address] += 1
                user_ips[username].add(ip_address)

                print(
                    "[LOG] Failed login | User:", username,
                    "| IP:", ip_address,
                    "| Time:", timestamp
                )

    print("\n=== Cloud Identity Threat Detector ===")

    alerts_found = False

    for username, count in sorted(failed_attempts.items()):
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts_found = True
            print("\n[HIGH] Repeated failed logins detected")
            print("User:", username)
            print("Failed attempts:", count)
            print("Source IPs:", ", ".join(sorted(user_ips[username])))

    for ip_address, count in sorted(failed_by_ip.items()):
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts_found = True
            print("\n[MEDIUM] Multiple failures from one IP")
            print("IP address:", ip_address)
            print("Failed attempts:", count)

    if not alerts_found:
        print("\nNo suspicious login patterns detected.")

except FileNotFoundError:
    print("Error: login_logs.csv file not found.")
except ValueError as error:
    print("Error:", error)
