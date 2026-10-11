#!/usr/bin/env python3
"""
Wi-Fi Quality Tester: Windows, macOS, Linux
Python 3.9+, no third-party packages required.

Measures local AP ping latency/loss under concurrent ICMP load and collects
OS/driver Wi-Fi telemetry where available. Retry counters are actual driver
counters when exposed; unsupported metrics are shown as N/A.

Examples:
  python wifi_quality.py 192.168.1.1
  python wifi_quality.py 192.168.1.1 --duration 300 --load 8
  python wifi_quality.py 192.168.1.1 --interface wlan0 --csv results.csv
"""

import argparse
import csv
import ctypes
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import uuid
from collections import deque
from statistics import mean


def run_cmd(command, timeout=3):
    try:
        p = subprocess.run(command, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def ping_once(host, timeout):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    elif system == "Darwin":
        # macOS ping -W is milliseconds.
        cmd = ["ping", "-n", "-c", "1", "-W", str(int(timeout * 1000)), host]
    else:
        # iputils ping -W is seconds; minimum 1 second on common Linux builds.
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), host]

    started = time.monotonic()
    rc, output = run_cmd(cmd, timeout=timeout + 1.5)
    elapsed = (time.monotonic() - started) * 1000
    if rc != 0:
        return False, None

    # Output formats vary by OS and language. Prefer reported ICMP RTT.
    patterns = [
        r"time[=<]\s*([\d.,]+)\s*ms",
        r"time[=<]\s*([\d.,]+)\s*мс",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            try:
                return True, float(match.group(1).replace(",", "."))
            except ValueError:
                pass
    # Process elapsed time is only a fallback, and includes process startup.
    return True, elapsed


def get_linux_interface():
    rc, out = run_cmd(["iw", "dev"], timeout=2)
    if rc != 0:
        return None
    matches = re.findall(r"^\s*Interface\s+(\S+)", out, re.MULTILINE)
    return matches[0] if matches else None


def linux_telemetry(interface=None):
    if not shutil.which("iw"):
        return {"status": "iw not installed", "retries": None, "failed": None,
                "signal_dbm": None, "tx_packets": None, "rx_packets": None,
                "tx_bitrate": None}
    interface = interface or get_linux_interface()
    if not interface:
        return {"status": "no Wi-Fi interface detected", "retries": None,
                "failed": None, "signal_dbm": None, "tx_packets": None,
                "rx_packets": None, "tx_bitrate": None}
    rc, out = run_cmd(["iw", "dev", interface, "link"], timeout=2)
    if rc != 0 or "Not connected" in out:
        return {"status": f"{interface}: not connected / link unavailable",
                "retries": None, "failed": None, "signal_dbm": None,
                "tx_packets": None, "rx_packets": None, "tx_bitrate": None,
                "interface": interface}
    link = out
    # On a Wi-Fi client, station get <AP-MAC> is more likely to return
    # counters than station dump (which commonly lists clients in AP mode).
    peer = re.search(r"^Connected to\s+([0-9a-f:]{17})", link, re.MULTILINE | re.IGNORECASE)
    station = ""
    rc2 = 1
    if peer:
        rc2, station = run_cmd(
            ["iw", "dev", interface, "station", "get", peer.group(1)], timeout=2
        )
    text = station if rc2 == 0 and station.strip() else link

    def number(pattern, source=text, cast=int):
        m = re.search(pattern, source, re.IGNORECASE | re.MULTILINE)
        if not m:
            return None
        try:
            return cast(m.group(1))
        except (ValueError, TypeError):
            return None

    signal = number(r"^\s*signal:\s*(-?\d+)\s*dBm", link)
    tx_rate = number(r"^\s*tx bitrate:\s*([\d.]+)\s*MBit/s", link, float)
    if tx_rate is None:
        tx_rate = number(r"^\s*tx bitrate:\s*([\d.]+)\s*MBit/s", text, float)
    return {
        "status": f"{interface}: connected" + ("; driver counters available" if
                 number(r"^\s*tx retries:\s*(\d+)", text) is not None else
                 "; retry counters unavailable from this driver"),
        "interface": interface,
        "retries": number(r"^\s*tx retries:\s*(\d+)", text),
        "failed": number(r"^\s*tx failed:\s*(\d+)", text),
        "signal_dbm": signal,
        "tx_packets": number(r"^\s*tx packets:\s*(\d+)", text),
        "rx_packets": number(r"^\s*rx packets:\s*(\d+)", text),
        "tx_bitrate": tx_rate,
    }


def windows_telemetry():
    """Query Windows Native Wi-Fi WLAN_STATISTICS PHY retry counters via ctypes."""
    unavailable = {"status": "Windows Native Wi-Fi statistics unavailable",
                   "retries": None, "failed": None, "signal_dbm": None,
                   "tx_packets": None, "rx_packets": None, "tx_bitrate": None}
    if platform.system() != "Windows":
        return unavailable
    try:
        wlan = ctypes.WinDLL("wlanapi.dll")
        DWORD = ctypes.c_uint32
        ULONGLONG = ctypes.c_uint64
        HANDLE = ctypes.c_void_p

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                        ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256),
                        ("isState", DWORD)]

        class WLAN_INTERFACE_INFO_LIST_HEAD(ctypes.Structure):
            _fields_ = [("dwNumberOfItems", DWORD), ("dwIndex", DWORD)]

        class MAC_STATS(ctypes.Structure):
            _fields_ = [(name, ULONGLONG) for name in (
                "ullTransmittedFrameCount", "ullReceivedFrameCount", "ullWEPExcludedCount",
                "ullTKIPLocalMICFailures", "ullTKIPReplays", "ullTKIPICVErrorCount",
                "ullCCMPReplays", "ullCCMPDecryptErrors", "ullWEPUndecryptableCount",
                "ullWEPICVErrorCount", "ullDecryptSuccessCount", "ullDecryptFailureCount")]

        class PHY_STATS(ctypes.Structure):
            _fields_ = [(name, ULONGLONG) for name in (
                "ullTransmittedFrameCount", "ullMulticastTransmittedFrameCount",
                "ullFailedCount", "ullRetryCount", "ullMultipleRetryCount",
                "ullMaxTXLifetimeExceededCount", "ullTransmittedFragmentCount",
                "ullRTSSuccessCount", "ullRTSFailureCount", "ullACKFailureCount",
                "ullReceivedFrameCount", "ullMulticastReceivedFrameCount",
                "ullPromiscuousReceivedFrameCount", "ullMaxRXLifetimeExceededCount",
                "ullFrameDuplicateCount", "ullReceivedFragmentCount",
                "ullPromiscuousReceivedFragmentCount", "ullFCSErrorCount")]

        class WLAN_STATS_PREFIX(ctypes.Structure):
            _fields_ = [("ullFourWayHandshakeFailures", ULONGLONG),
                        ("ullTKIPCounterMeasuresInvoked", ULONGLONG),
                        ("ullReserved", ULONGLONG),
                        ("MacUcastCounters", MAC_STATS),
                        ("MacMcastCounters", MAC_STATS),
                        ("dwNumberOfPhys", DWORD)]

        wlan.WlanOpenHandle.argtypes = [DWORD, ctypes.c_void_p,
                                        ctypes.POINTER(DWORD), ctypes.POINTER(HANDLE)]
        wlan.WlanOpenHandle.restype = DWORD
        wlan.WlanEnumInterfaces.argtypes = [HANDLE, ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_void_p)]
        wlan.WlanEnumInterfaces.restype = DWORD
        wlan.WlanQueryInterface.argtypes = [HANDLE, ctypes.POINTER(GUID), DWORD,
                                             ctypes.c_void_p, ctypes.POINTER(DWORD),
                                             ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(DWORD)]
        wlan.WlanQueryInterface.restype = DWORD
        wlan.WlanFreeMemory.argtypes = [ctypes.c_void_p]
        wlan.WlanCloseHandle.argtypes = [HANDLE, ctypes.c_void_p]

        negotiated = DWORD()
        handle = HANDLE()
        if wlan.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle)) != 0:
            return unavailable
        interface_list = ctypes.c_void_p()
        try:
            if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(interface_list)) != 0:
                return unavailable
            head = ctypes.cast(interface_list, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST_HEAD)).contents
            if head.dwNumberOfItems == 0:
                return {**unavailable, "status": "No Windows Wi-Fi interfaces found"}
            # Interface entries immediately follow the two-DWORD list header.
            entries_addr = interface_list.value + ctypes.sizeof(WLAN_INTERFACE_INFO_LIST_HEAD)
            entries = ctypes.cast(entries_addr, ctypes.POINTER(WLAN_INTERFACE_INFO))
            chosen = None
            for idx in range(head.dwNumberOfItems):
                item = entries[idx]
                # WLAN_INTERFACE_STATE_CONNECTED == 1
                if item.isState == 1:
                    chosen = item
                    break
            if chosen is None:
                return {**unavailable, "status": "No connected Windows Wi-Fi interface"}
            guid = chosen.InterfaceGuid
            data_size, data_ptr, opcode_type = DWORD(), ctypes.c_void_p(), DWORD()
            # wlan_intf_opcode_statistics = 0x10000000
            rc = wlan.WlanQueryInterface(handle, ctypes.byref(guid), 0x10000000,
                                         None, ctypes.byref(data_size),
                                         ctypes.byref(data_ptr), ctypes.byref(opcode_type))
            if rc != 0 or not data_ptr:
                return {**unavailable, "status": f"{chosen.strInterfaceDescription}: statistics API unavailable"}
            try:
                prefix = ctypes.cast(data_ptr, ctypes.POINTER(WLAN_STATS_PREFIX)).contents
                count = min(int(prefix.dwNumberOfPhys), 64)
                base = data_ptr.value + ctypes.sizeof(WLAN_STATS_PREFIX)
                # Current Windows SDKs describe PhyCounters as an array of
                # pointers to PHY counter structures. The returned pointers
                # are supplied by the WLAN API in the returned allocation.
                ptr_array = ctypes.cast(base, ctypes.POINTER(ctypes.c_void_p))
                phys = []
                for i in range(count):
                    ptr = ptr_array[i]
                    if ptr:
                        phys.append(ctypes.cast(ptr, ctypes.POINTER(PHY_STATS)).contents)
                if not phys:
                    return {**unavailable, "status": "Windows driver returned no readable PHY counters"}
                retries = sum(int(p.ullRetryCount) for p in phys)
                failed = sum(int(p.ullFailedCount) for p in phys)
                tx = sum(int(p.ullTransmittedFrameCount) for p in phys)
                rx = sum(int(p.ullReceivedFrameCount) for p in phys)
                return {"status": f"{chosen.strInterfaceDescription}: Native Wi-Fi PHY counters",
                        "interface": chosen.strInterfaceDescription,
                        "retries": retries, "failed": failed, "signal_dbm": None,
                        "tx_packets": tx, "rx_packets": rx, "tx_bitrate": None}
            finally:
                wlan.WlanFreeMemory(data_ptr)
        finally:
            if interface_list:
                wlan.WlanFreeMemory(interface_list)
            wlan.WlanCloseHandle(handle, None)
    except Exception as exc:
        return {**unavailable, "status": f"Windows telemetry error: {exc}"}


def macos_telemetry():
    """macOS exposes RSSI/rate through airport/wdutil on some versions, but
    does not provide a stable public per-client retry-counter API."""
    info = {"status": "macOS: retry counters not available through supported public CLI",
            "retries": None, "failed": None, "signal_dbm": None,
            "tx_packets": None, "rx_packets": None, "tx_bitrate": None}
    # airport -I is deprecated/absent on newer macOS; use only if present.
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if os.path.exists(airport):
        rc, out = run_cmd([airport, "-I"], timeout=3)
        if rc == 0:
            m = re.search(r"^\s* agrCtlRSSI:\s*(-?\d+)", out, re.MULTILINE)
            if m:
                info["signal_dbm"] = int(m.group(1))
            info["status"] = "macOS: RSSI available; retry counters N/A"
    return info


def telemetry(interface=None):
    system = platform.system()
    if system == "Windows":
        return windows_telemetry()
    if system == "Linux":
        return linux_telemetry(interface)
    if system == "Darwin":
        return macos_telemetry()
    return {"status": f"Unsupported OS: {system}", "retries": None, "failed": None,
            "signal_dbm": None, "tx_packets": None, "rx_packets": None, "tx_bitrate": None}


def assess(loss_pct, p95, jitter, retry_pct=None, failed_pct=None, signal=None):
    # Poor if any strong failure indicator crosses its threshold.
    if loss_pct > 5 or p95 > 150 or jitter > 40 or (retry_pct is not None and retry_pct > 35) or (failed_pct is not None and failed_pct > 5):
        return "POOR"
    if loss_pct > 2 or p95 > 80 or jitter > 20 or (retry_pct is not None and retry_pct > 20) or (failed_pct is not None and failed_pct > 2):
        return "FAIR"
    if loss_pct > 1 or p95 > 40 or jitter > 10 or (retry_pct is not None and retry_pct > 10) or (failed_pct is not None and failed_pct > 1):
        return "GOOD"
    # If radio counters are missing, rating is based on network measurements only.
    return "EXCELLENT"


def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, max(0, math.ceil(pct / 100 * len(values)) - 1))]


def fmt(value, suffix="", digits=1):
    return "N/A" if value is None else f"{value:.{digits}f}{suffix}"


def main():
    parser = argparse.ArgumentParser(description="Cross-platform Wi-Fi quality tester with OS telemetry")
    parser.add_argument("ap", help="AP/router LAN IP or hostname, e.g. 192.168.1.1")
    parser.add_argument("-d", "--duration", type=int, default=120, help="Duration in seconds (default: 120)")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Seconds between probe rounds (default: 1)")
    parser.add_argument("-l", "--load", type=int, default=4, help="Extra concurrent pings per round (default: 4)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Ping timeout in seconds (default: 1)")
    parser.add_argument("--interface", help="Wi-Fi interface name (mainly Linux, e.g. wlan0)")
    parser.add_argument("--csv", help="Write per-interval samples to this CSV file")
    args = parser.parse_args()
    if args.duration < 1 or args.interval <= 0 or args.load < 0 or args.timeout <= 0:
        parser.error("Duration, interval and timeout must be positive; load cannot be negative.")
    if not shutil.which("ping"):
        sys.exit("ERROR: ping was not found. Check that it is installed and on PATH.")

    print("\nWI-FI QUALITY TEST")
    print("=" * 78)
    print(f"Target: {args.ap} | Duration: {args.duration}s | Concurrent pings/round: {args.load + 1}")
    print(f"OS: {platform.system()} {platform.release()}")
    print("Radio telemetry is sampled from OS/driver counters when available.")
    print("Press Ctrl+C to stop early.\n")

    baseline = telemetry(args.interface)
    print(f"Radio source : {baseline.get('status', 'unknown')}")
    print(f"Interface    : {baseline.get('interface', 'auto / OS-selected')}")
    print(f"Signal       : {fmt(baseline.get('signal_dbm'), ' dBm', 0)}")
    print("Starting counters captured. Retry/failure figures below are interval deltas.\n")

    csv_file = None
    csv_writer = None
    if args.csv:
        try:
            csv_file = open(args.csv, "w", newline="", encoding="utf-8")
            csv_writer = csv.DictWriter(csv_file, fieldnames=[
                "elapsed_s", "quality", "avg_ms", "p95_ms", "jitter_ms", "loss_pct",
                "retry_delta", "tx_delta", "retry_pct", "failed_delta", "failed_pct",
                "signal_dbm"])
            csv_writer.writeheader()
        except OSError as exc:
            sys.exit(f"Cannot open CSV file: {exc}")

    probes = deque()
    latencies = []
    total = lost = 0
    retry_deltas, tx_deltas, fail_deltas = 0, 0, 0
    radio_valid_rounds = 0
    start = time.monotonic()
    end = start + args.duration
    last_radio = baseline
    last_radio_time = start
    quality_counts = {k: 0 for k in ("EXCELLENT", "GOOD", "FAIR", "POOR")}

    try:
        while time.monotonic() < end:
            round_start = time.monotonic()
            # Concurrent ping subprocesses provide a modest ICMP probe load.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.load + 1) as pool:
                futures = [pool.submit(ping_once, args.ap, args.timeout) for _ in range(args.load + 1)]
                results = []
                for future in futures:
                    try:
                        results.append(future.result())
                    except Exception:
                        results.append((False, None))

            now = time.monotonic()
            for ok, rtt in results:
                total += 1
                if not ok:
                    lost += 1
                else:
                    latencies.append(rtt)
                    probes.append((now, rtt))
            while probes and probes[0][0] < now - 30:
                probes.popleft()
            recent = [x[1] for x in probes]
            recent_total = min(total, max(1, round(30 / args.interval) * (args.load + 1)))
            # Rolling loss is based on recent probe records, including failed ones.
            # Maintain a second timestamped list so losses aren't hidden.
            if not hasattr(main, "_all_recent"):
                main._all_recent = deque()
            recent_all = main._all_recent
            for ok, rtt in results:
                recent_all.append((now, ok, rtt))
            while recent_all and recent_all[0][0] < now - 30:
                recent_all.popleft()
            window_loss = 100 * sum(not x[1] for x in recent_all) / len(recent_all) if recent_all else 0
            jitter = mean(abs(b - a) for a, b in zip(recent, recent[1:])) if len(recent) >= 2 else 0.0
            p95 = percentile(recent, 95)

            current = telemetry(args.interface)
            retry_delta = tx_delta = fail_delta = None
            retry_pct = failed_pct = None
            if current.get("retries") is not None and last_radio.get("retries") is not None:
                retry_delta = max(0, current["retries"] - last_radio["retries"])
                tx_delta = max(0, current["tx_packets"] - last_radio["tx_packets"]) if current.get("tx_packets") is not None and last_radio.get("tx_packets") is not None else None
                fail_delta = max(0, current["failed"] - last_radio["failed"]) if current.get("failed") is not None and last_radio.get("failed") is not None else None
                if tx_delta is not None and tx_delta > 0:
                    retry_pct = 100 * retry_delta / tx_delta
                if tx_delta is not None and tx_delta > 0 and fail_delta is not None:
                    failed_pct = 100 * fail_delta / tx_delta
                radio_valid_rounds += 1
                retry_deltas += retry_delta
                if tx_delta is not None:
                    tx_deltas += tx_delta
                if fail_delta is not None:
                    fail_deltas += fail_delta
            last_radio, last_radio_time = current, now
            signal = current.get("signal_dbm")
            quality = assess(window_loss, p95, jitter, retry_pct, failed_pct, signal)
            quality_counts[quality] += 1
            elapsed = int(now - start)
            retry_text = f"{retry_pct:.1f}%" if retry_pct is not None else "N/A"
            fail_text = f"{failed_pct:.1f}%" if failed_pct is not None else "N/A"
            signal_text = f"{signal} dBm" if signal is not None else "N/A"
            avg = mean(recent) if recent else None
            print(f"\r[{elapsed:4d}s] {quality:9s} | avg {fmt(avg, ' ms'):>9s} | "
                  f"P95 {p95:6.1f} ms | jitter {jitter:5.1f} ms | "
                  f"loss {window_loss:5.1f}% | retries {retry_text:>6s} | "
                  f"failed {fail_text:>6s} | RSSI {signal_text:>7s}   ",
                  end="", flush=True)
            if csv_writer:
                csv_writer.writerow({
                    "elapsed_s": elapsed, "quality": quality,
                    "avg_ms": round(avg, 2) if avg is not None else "",
                    "p95_ms": round(p95, 2), "jitter_ms": round(jitter, 2),
                    "loss_pct": round(window_loss, 2),
                    "retry_delta": retry_delta if retry_delta is not None else "",
                    "tx_delta": tx_delta if tx_delta is not None else "",
                    "retry_pct": round(retry_pct, 2) if retry_pct is not None else "",
                    "failed_delta": fail_delta if fail_delta is not None else "",
                    "failed_pct": round(failed_pct, 2) if failed_pct is not None else "",
                    "signal_dbm": signal if signal is not None else "",
                })
                csv_file.flush()
            remaining = args.interval - (time.monotonic() - round_start)
            if remaining > 0:
                time.sleep(min(remaining, max(0, end - time.monotonic())))
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        if csv_file:
            csv_file.close()

    duration = time.monotonic() - start
    overall_loss = 100 * lost / total if total else 100
    overall_jitter = mean(abs(b - a) for a, b in zip(latencies, latencies[1:])) if len(latencies) >= 2 else 0.0
    overall_p95 = percentile(latencies, 95)
    overall_retry_pct = 100 * retry_deltas / tx_deltas if tx_deltas > 0 else None
    overall_failed_pct = 100 * fail_deltas / tx_deltas if tx_deltas > 0 else None
    overall = assess(overall_loss, overall_p95, overall_jitter, overall_retry_pct, overall_failed_pct)

    print("\n\n" + "=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)
    print(f"Overall quality       : {overall}")
    print(f"Duration / probes     : {duration:.1f}s / {total}")
    print(f"Packet loss           : {lost}/{total} ({overall_loss:.2f}%)")
    if latencies:
        print(f"Average latency       : {mean(latencies):.1f} ms")
        print(f"95th percentile       : {overall_p95:.1f} ms")
        print(f"Minimum / maximum RTT : {min(latencies):.1f} / {max(latencies):.1f} ms")
        print(f"Mean RTT variation    : {overall_jitter:.1f} ms")
    else:
        print("Latency               : no successful pings")
    print(f"Radio telemetry       : {last_radio.get('status', 'unavailable')}")
    print(f"RSSI                  : {fmt(last_radio.get('signal_dbm'), ' dBm', 0)}")
    print(f"Retry counter delta   : {retry_deltas if radio_valid_rounds else 'N/A'}")
    print(f"Successful TX frames* : {tx_deltas if radio_valid_rounds else 'N/A'}")
    print(f"Failed TX delta       : {fail_deltas if radio_valid_rounds else 'N/A'}")
    print(f"Overall retry ratio   : {fmt(overall_retry_pct, '%')}")
    print(f"Overall failure ratio : {fmt(overall_failed_pct, '%')}")
    if args.csv:
        print(f"CSV log               : {args.csv}")
    print("\nQuality categories use latency/loss plus radio counters when available.")
    print("* Frame counter semantics vary by driver/OS; retry ratio is indicative,")
    print("  not a universal cross-vendor PHY score. N/A means not exposed.")
    print("=" * 78)


if __name__ == "__main__":
    main()
