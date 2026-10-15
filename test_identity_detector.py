
import unittest
from collections import Counter


def detect_failed_logins(rows, threshold=3):
    failed_users = Counter()
    failed_ips = Counter()

    for row in rows:
        if row["status"].strip().lower() == "failed":
            failed_users[row["username"]] += 1
            failed_ips[row["ip_address"]] += 1

    user_alerts = {
        user: count
        for user, count in failed_users.items()
        if count >= threshold
    }

    ip_alerts = {
        ip: count
        for ip, count in failed_ips.items()
        if count >= threshold
    }

    return user_alerts, ip_alerts


class TestIdentityDetector(unittest.TestCase):

    def test_repeated_failed_logins(self):
        rows = [
            {"username": "rahul", "status": "failed",
             "ip_address": "203.0.113.25"},
            {"username": "rahul", "status": "failed",
             "ip_address": "203.0.113.25"},
            {"username": "rahul", "status": "failed",
             "ip_address": "203.0.113.25"},
        ]

        users, ips = detect_failed_logins(rows)

        self.assertEqual(users["rahul"], 3)
        self.assertEqual(ips["203.0.113.25"], 3)

    def test_successful_logins_do_not_trigger_alert(self):
        rows = [
            {"username": "priya", "status": "success",
             "ip_address": "192.0.2.10"}
        ]

        users, ips = detect_failed_logins(rows)

        self.assertEqual(users, {})
        self.assertEqual(ips, {})

    def test_below_threshold(self):
        rows = [
            {"username": "amit", "status": "failed",
             "ip_address": "192.0.2.20"},
            {"username": "amit", "status": "failed",
             "ip_address": "192.0.2.20"},
        ]

        users, ips = detect_failed_logins(rows)

        self.assertEqual(users, {})
        self.assertEqual(ips, {})


if __name__ == "__main__":
    unittest.main()
