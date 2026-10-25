
import unittest
from collections import Counter


class TestLogGuard(unittest.TestCase):

    def test_failed_login_count(self):
        events = [
            "LOGIN_FAILED",
            "LOGIN_SUCCESS",
            "LOGIN_FAILED",
            "LOGIN_FAILED"
        ]

        failed_count = events.count("LOGIN_FAILED")
        self.assertEqual(failed_count, 3)

    def test_suspicious_ip_threshold(self):
        failed_ips = Counter({
            "203.0.113.25": 3,
            "198.51.100.8": 2
        })

        suspicious_ips = [
            ip for ip, attempts in failed_ips.items()
            if attempts >= 3
        ]

        self.assertEqual(suspicious_ips, ["203.0.113.25"])

    def test_no_suspicious_activity(self):
        failed_ips = Counter({
            "192.0.2.10": 1,
            "192.0.2.20": 2
        })

        suspicious_ips = [
            ip for ip, attempts in failed_ips.items()
            if attempts >= 3
        ]

        self.assertEqual(suspicious_ips, [])


if __name__ == "__main__":
    unittest.main()
