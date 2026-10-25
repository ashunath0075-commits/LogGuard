
import csv
from collections import Counter

LOG_FILE = "sample_logs.csv"
REPORT_FILE = "security_report.txt"
FAILURE_THRESHOLD = 3


def analyze_logs():
    success_count = 0
    failed_count = 0
    failed_ips = Counter()

    with open(LOG_FILE, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        for row in reader:
            event = row["event"].strip()
            ip = row["ip"].strip()

            if event == "LOGIN_SUCCESS":
                success_count += 1
            elif event == "LOGIN_FAILED":
                failed_count += 1
                failed_ips[ip] += 1

    total_events = success_count + failed_count

    report = []
    report.append("===== LOGGUARD SECURITY REPORT =====")
    report.append(f"Successful logins: {success_count}")
    report.append(f"Failed logins: {failed_count}")
    report.append(f"Total login events: {total_events}")
    report.append("")
    report.append("===== SUSPICIOUS ACTIVITY =====")

    suspicious_found = False

    for ip, attempts in failed_ips.items():
        if attempts >= FAILURE_THRESHOLD:
            report.append(
                f"ALERT: {ip} had {attempts} failed login attempts!"
            )
            suspicious_found = True

    if not suspicious_found:
        report.append("No suspicious activity detected.")

    report_text = "\n".join(report)

    print(report_text)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(report_text + "\n")

    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_logs()
