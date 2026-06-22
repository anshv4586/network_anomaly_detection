#!/usr/bin/env python3
"""
Generate a realistic sample network log file with planted anomalies.
Run this once to produce sample_logs/network_traffic.log before running the detector.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

random.seed(42)
np.random.seed(42)

BASE_DATE = datetime(2024, 1, 15)

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(1, 50)]
EXTERNAL_IPS = [
    "10.0.14.22", "10.0.88.5", "10.0.3.200", "10.0.55.17",
    "10.0.120.9", "10.0.7.88", "10.0.44.1", "10.0.99.33",
    "10.0.200.4", "10.0.31.60", "10.0.77.150", "10.0.11.11",
]
COMMON_PORTS = [80, 443, 22, 21, 53, 8080, 8443, 3306, 5432, 25, 587, 993, 3389]


def gen_normal_traffic(n, start_time, end_time):
    entries = []
    span = (end_time - start_time).total_seconds()
    for _ in range(n):
        ts = start_time + timedelta(seconds=random.uniform(0, span))
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
        port = random.choice(COMMON_PORTS)
        proto = "UDP" if port == 53 else "TCP"
        # log-normal byte distribution: mostly small, occasionally larger
        bytes_val = max(64, int(np.random.lognormal(7, 1)))
        status = "FAILED" if random.random() < 0.04 else "SUCCESS"
        duration = max(1, int(np.random.exponential(120)))
        entries.append([ts, src, dst, port, proto, bytes_val, status, duration])
    return entries


def gen_night_activity(n=65):
    """Anomaly 1 — unusual burst of connections at 02:20 from one internal host."""
    entries = []
    start = BASE_DATE.replace(hour=2, minute=20)
    host = "192.168.1.50"
    for _ in range(n):
        ts = start + timedelta(seconds=random.uniform(0, 600))
        entries.append([ts, host, "203.0.113.50", 443, "TCP",
                        int(np.random.uniform(1_000, 50_000)), "SUCCESS",
                        int(np.random.exponential(200))])
    return entries


def gen_traffic_spike(n=520):
    """Anomaly 2 — sudden 500x traffic spike at 10:28 (possible DDoS ingest)."""
    entries = []
    start = BASE_DATE.replace(hour=10, minute=28)
    attacker = "45.33.32.156"
    targets = INTERNAL_IPS[:10]
    for _ in range(n):
        ts = start + timedelta(seconds=random.uniform(0, 300))
        entries.append([ts, attacker, random.choice(targets),
                        random.choice([80, 443, 8080]), "TCP",
                        int(np.random.uniform(50_000, 500_000)),
                        "SUCCESS", int(np.random.exponential(50))])
    return entries


def gen_port_scan(n=320):
    """Anomaly 3 — sequential port scan at 13:58 from rogue internal host."""
    entries = []
    start = BASE_DATE.replace(hour=13, minute=58)
    scanner = "192.168.100.50"
    target = "192.168.1.1"
    for i in range(n):
        ts = start + timedelta(seconds=i * 0.45)
        port = 1 + (i % 1024)
        entries.append([ts, scanner, target, port, "TCP", 60,
                        "FAILED" if random.random() > 0.08 else "SUCCESS",
                        int(np.random.uniform(1, 80))])
    return entries


def gen_brute_force(n=85):
    """Anomaly 4 — SSH brute-force at 16:27 (many rapid failed logins)."""
    entries = []
    start = BASE_DATE.replace(hour=16, minute=27)
    attacker = "192.168.200.1"
    target = "192.168.1.5"
    for _ in range(n):
        ts = start + timedelta(seconds=random.uniform(0, 300))
        entries.append([ts, attacker, target, 22, "TCP",
                        int(np.random.uniform(200, 800)), "FAILED",
                        int(np.random.uniform(100, 500))])
    return entries


def gen_exfiltration(n=210):
    """Anomaly 5 — sustained large outbound transfer at 19:43 (data exfil)."""
    entries = []
    start = BASE_DATE.replace(hour=19, minute=43)
    insider = "192.168.1.25"
    c2 = "198.51.100.25"
    for _ in range(n):
        ts = start + timedelta(seconds=random.uniform(0, 900))
        entries.append([ts, insider, c2, 443, "TCP",
                        int(np.random.uniform(500_000, 2_000_000)),
                        "SUCCESS", int(np.random.uniform(500, 2000))])
    return entries


def main():
    print("Generating sample network log ...")
    all_entries = []

    # Realistic connection counts per hour (business-hours peak)
    hourly_counts = {
        0: 30,  1: 18,  2: 30,  3: 18,  4: 30,  5: 48,
        6: 120, 7: 240, 8: 480, 9: 600, 10: 540, 11: 510,
        12: 420, 13: 540, 14: 570, 15: 510, 16: 450, 17: 360,
        18: 270, 19: 240, 20: 210, 21: 150, 22: 90, 23: 48,
    }

    for hour, count in hourly_counts.items():
        start = BASE_DATE.replace(hour=hour)
        end = start + timedelta(hours=1)
        all_entries.extend(gen_normal_traffic(count, start, end))

    print("  Injecting anomalies ...")
    all_entries.extend(gen_night_activity())
    all_entries.extend(gen_traffic_spike())
    all_entries.extend(gen_port_scan())
    all_entries.extend(gen_brute_force())
    all_entries.extend(gen_exfiltration())

    df = pd.DataFrame(all_entries,
                      columns=["timestamp", "src_ip", "dst_ip", "dst_port",
                               "protocol", "bytes", "status", "duration_ms"])
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    os.makedirs("sample_logs", exist_ok=True)
    out = "sample_logs/network_traffic.log"
    df.to_csv(out, index=False)

    print(f"\n  Written {len(df):,} log entries -> {out}")
    print("\n  Planted anomalies:")
    print("    #1  Night Activity    02:20-02:30  off-hours internal host burst")
    print("    #2  Traffic Spike     10:28-10:33  high-volume inbound flood")
    print("    #3  Port Scan         13:58-14:01  sequential port sweep")
    print("    #4  Brute Force       16:27-16:32  SSH failed-login storm")
    print("    #5  Data Exfiltration 19:43-20:00  sustained large outbound transfer")


if __name__ == "__main__":
    main()
