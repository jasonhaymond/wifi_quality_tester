Wi-Fi Quality Tester
====================

Files
-----
wifi_quality.py   Cross-platform test script (Windows, macOS, Linux)

Requirements
------------
- Python 3.9 or newer
- The system `ping` command
- Linux: `iw` is optional, but needed for Linux driver telemetry
- No Python packages are required

Run
---
Windows PowerShell:
  py .\wifi_quality.py 192.168.1.1

macOS / Linux:
  python3 wifi_quality.py 192.168.1.1

Replace 192.168.1.1 with the LAN IP of the AP/router you want to test.

Examples
--------
Quick 30-second test:
  python3 wifi_quality.py 192.168.1.1 --duration 30 --load 2

Five-minute test with heavier concurrent ping load:
  python3 wifi_quality.py 192.168.1.1 --duration 300 --load 8

Select a Linux Wi-Fi interface:
  python3 wifi_quality.py 192.168.1.1 --interface wlan0

Save per-interval measurements to CSV:
  python3 wifi_quality.py 192.168.1.1 --csv wifi-results.csv

Options
-------
-d / --duration SECONDS    Test length (default 120)
-i / --interval SECONDS    Time between rounds (default 1)
-l / --load COUNT          Extra concurrent pings per round (default 4)
-t / --timeout SECONDS     Ping timeout (default 1)
--interface NAME           Choose a Wi-Fi interface (primarily Linux)
--csv FILE                 Save a CSV log

Telemetry notes
---------------
- Linux uses `iw` and driver-reported station statistics when supported.
- Windows queries Native Wi-Fi PHY counters through wlanapi.dll. Some drivers
  may not expose useful counters or may return no PHY data.
- macOS reports RSSI only when available through the legacy airport utility.
  macOS does not provide a stable supported public CLI for comparable retry
  counters, so retry/failure values are marked N/A.
- Counter deltas are sampled between intervals. The ratio is indicative:
  drivers and operating systems may define packet/frame counters differently.
- The script measures the local client's exposed radio counters, not retries
  observed by the AP itself.
- ICMP load is a diagnostic probe load, not a bandwidth/throughput test.
  For best results, target the AP's LAN address. Some routers rate-limit pings.
- Run a test near the AP and another at the problem location to compare results.
