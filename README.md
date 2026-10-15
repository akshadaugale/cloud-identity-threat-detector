# Cloud Identity Threat Detector

## Overview
A Python-based Blue Team cybersecurity tool that analyzes synthetic cloud identity login logs and detects repeated failed login attempts.

## Features
- Reads login events from a CSV file.
- Counts failed login attempts per username.
- Detects repeated failures from an IP address.
- Generates HIGH and MEDIUM alerts.
- Displays the source IP address and event timestamps.

## Technologies
- Python 3
- CSV
- `collections.Counter`
- `collections.defaultdict`

## Project Files
- `identity_detector.py` — Detection logic.
- `login_logs.csv` — Synthetic login event dataset.
- `README.md` — Project documentation.

## How to Run
1. Install Python 3.
2. Open the project directory in VS Code.
3. Run:

   `py identity_detector.py`

## Detection Logic
- HIGH: Three or more failed attempts associated with one username.
- MEDIUM: Three or more failed attempts associated with one IP address.

## Testing
The tool was tested with synthetic login records containing successful and failed login events. It detected four failed attempts for the test user `rahul` and four failures from the example IP address `203.0.113.25`.

## Limitations
This is a basic demonstration using synthetic CSV data. Alerts are indicators for investigation, not proof of account compromise. The current version does not perform live cloud monitoring or automatic blocking.

## Future Improvements
- Time-window-based detection.
- Detection of one IP targeting multiple users.
- JSON logging and alert reports.
- Unit tests and configurable thresholds.

## Disclaimer
For educational and authorized defensive security testing only. No real user credentials or production logs are included.