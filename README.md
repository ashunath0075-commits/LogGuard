
# LogGuard - Security Log Analyzer

LogGuard is a Python-based security log analyzer that reads login events from a CSV file, identifies repeated failed login attempts, and generates a security report.

## Features

- Analyzes login events from CSV files
- Counts successful and failed logins
- Tracks failed login attempts by IP address
- Flags IP addresses with repeated failed logins
- Exports results to a text report
- Includes automated unit tests

## Technologies Used

- Python
- CSV data processing
- Collections (`Counter`)
- Unit testing (`unittest`)

## Project Structure

LogGuard/
├── logguard.py
├── sample_logs.csv
├── security_report.txt
├── test_logguard.py
└── README.md

## How to Run

1. Install Python 3.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Run the analyzer:

   python logguard.py

5. Run the tests:

   python -m unittest -v test_logguard.py

## Detection Logic

LogGuard flags an IP address when it has 3 or more failed login attempts in the provided log data.

The threshold can be changed using `FAILURE_THRESHOLD` in `logguard.py`.

## Sample Output

Successful logins: 3
Failed logins: 5
Total login events: 8

ALERT: 203.0.113.25 had 3 failed login attempts!

## Disclaimer

This project is an educational demonstration using sample log data. It is not a replacement for a production security monitoring system.
