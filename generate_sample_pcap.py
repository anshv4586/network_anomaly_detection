#!/usr/bin/env python3
"""
Generate a sample PCAP file with planted network anomalies.
Requires scapy:  pip install scapy
Output: sample_logs/network_traffic.pcap
"""

import random
import os
from datetime import datetime, timedelta

random.seed(42)

try:
    from scapy.all import IP, TCP, UDP, Raw, wrpcap, conf
    conf.verb = 0
except ImportError:
    raise SystemExit("scapy not installed.  Run: pip install scapy")

BASE_DATE = datetime(2024, 1, 15)
INTERNAL  = [f"192.168.1.{i}" for i in range(1, 50)]
EXTERNAL  = ["10.0.14.22", "10.0.88.5", "10.0.3.200", "10.0.55.17",
             "10.0.120.9", "10.0.7.88", "10.0.44.1", "10.0.99.33"]
COMMON_PORTS = [443, 80, 22, 8080, 3306, 5432]


def _ts(dt: datetime) -> float:
    return dt.timestamp()


def tcp_pkt(src, dst, sport, dport, flags, payload_size, t):
    payload = b"A" * min(payload_size, 1460)   # cap at real TCP MSS
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload)
    pkt.time = _ts(t)
    return pkt


def udp_pkt(src, dst, dport, size, t):
    pkt = IP(src=src, dst=dst) / UDP(sport=random.randint(1024, 65535), dport=dport) / Raw(b"Q" * min(size, 512))
    pkt.time = _ts(t)
    return pkt


packets = []


# ── Normal business-hours traffic ────────────────────────────────────────────
print("Generating normal traffic ...")
hourly_rate = {
    0: 4,  1: 2,  2: 4,  3: 2,  4: 4,  5: 6,
    6: 15, 7: 30, 8: 60, 9: 80, 10: 70, 11: 65,
    12: 50, 13: 65, 14: 70, 15: 60, 16: 55, 17: 40,
    18: 30, 19: 25, 20: 20, 21: 14, 22: 8, 23: 5,
}

for hour, rate in hourly_rate.items():
    t0 = BASE_DATE.replace(hour=hour)
    for _ in range(rate * 5):                          # ~5 connections per slot
        t     = t0 + timedelta(seconds=random.uniform(0, 3600))
        src   = random.choice(INTERNAL)
        dst   = random.choice(EXTERNAL)
        port  = random.choice(COMMON_PORTS)
        sport = random.randint(1024, 65535)
        size  = random.randint(100, 1460)

        if port == 53:
            packets.append(udp_pkt(src, dst, 53, random.randint(20, 100), t))
        else:
            # 3-way handshake + data + FIN
            packets.append(tcp_pkt(src, dst, sport, port, "S",  0,    t))
            packets.append(tcp_pkt(dst, src, port, sport, "SA", 0,    t + timedelta(milliseconds=10)))
            packets.append(tcp_pkt(src, dst, sport, port, "PA", size, t + timedelta(milliseconds=20)))
            packets.append(tcp_pkt(dst, src, port, sport, "PA", size // 3, t + timedelta(milliseconds=35)))
            packets.append(tcp_pkt(src, dst, sport, port, "FA", 0,    t + timedelta(milliseconds=50)))


# ── Anomaly 1 — Night Activity at 02:20 ──────────────────────────────────────
print("  [1/5] Injecting night activity  (02:20)  ...")
t0   = BASE_DATE.replace(hour=2, minute=20)
host = "192.168.1.50"
for _ in range(65):
    t     = t0 + timedelta(seconds=random.uniform(0, 600))
    sport = random.randint(1024, 65535)
    size  = random.randint(2000, 20000)
    packets.append(tcp_pkt(host, "203.0.113.50", sport, 443, "S",  0,    t))
    packets.append(tcp_pkt("203.0.113.50", host, 443, sport, "SA", 0,    t + timedelta(milliseconds=15)))
    packets.append(tcp_pkt(host, "203.0.113.50", sport, 443, "PA", size, t + timedelta(milliseconds=30)))
    packets.append(tcp_pkt(host, "203.0.113.50", sport, 443, "FA", 0,    t + timedelta(milliseconds=60)))


# ── Anomaly 2 — Traffic Spike at 10:28 ───────────────────────────────────────
print("  [2/5] Injecting traffic spike   (10:28)  ...")
t0       = BASE_DATE.replace(hour=10, minute=28)
attacker = "45.33.32.156"
for _ in range(480):
    t    = t0 + timedelta(seconds=random.uniform(0, 300))
    dst  = random.choice(INTERNAL[:10])
    port = random.choice([80, 443, 8080])
    packets.append(tcp_pkt(attacker, dst, random.randint(1024, 65535), port,
                           "PA", 1460, t))


# ── Anomaly 3 — Port Scan at 13:58 ───────────────────────────────────────────
print("  [3/5] Injecting port scan       (13:58)  ...")
t0      = BASE_DATE.replace(hour=13, minute=58)
scanner = "192.168.100.50"
target  = "192.168.1.1"
for i in range(320):
    t     = t0 + timedelta(seconds=i * 0.4)
    port  = 1 + i
    sport = random.randint(1024, 65535)
    packets.append(tcp_pkt(scanner, target, sport, port, "S", 0, t))
    # RST response — port closed
    if random.random() > 0.08:
        packets.append(tcp_pkt(target, scanner, port, sport, "R", 0,
                               t + timedelta(milliseconds=2)))


# ── Anomaly 4 — SSH Brute Force at 16:27 ─────────────────────────────────────
print("  [4/5] Injecting brute force     (16:27)  ...")
t0       = BASE_DATE.replace(hour=16, minute=27)
attacker = "192.168.200.1"
victim   = "192.168.1.5"
for _ in range(85):
    t     = t0 + timedelta(seconds=random.uniform(0, 300))
    sport = random.randint(1024, 65535)
    packets.append(tcp_pkt(attacker, victim, sport, 22, "S", 0, t))
    # Server rejects → RST
    packets.append(tcp_pkt(victim, attacker, 22, sport, "R", 0,
                           t + timedelta(milliseconds=100)))


# ── Anomaly 5 — Data Exfiltration at 19:43 ───────────────────────────────────
print("  [5/5] Injecting data exfiltration (19:43) ...")
t0      = BASE_DATE.replace(hour=19, minute=43)
insider = "192.168.1.25"
c2      = "198.51.100.25"
for i in range(200):
    t     = t0 + timedelta(seconds=i * 4.5)          # spread over ~15 min
    sport = 50000 + (i % 50)
    packets.append(tcp_pkt(insider, c2, sport, 443, "PA", 1460, t))


# ── Sort by time and write ────────────────────────────────────────────────────
print(f"\nSorting {len(packets):,} packets ...")
packets.sort(key=lambda p: float(p.time))

os.makedirs("sample_logs", exist_ok=True)
out = "sample_logs/network_traffic.pcap"
wrpcap(out, packets)

size_mb = os.path.getsize(out) / 1_048_576
print(f"Written {len(packets):,} packets  ({size_mb:.1f} MB)  ->  {out}")
print("""
Planted anomalies:
  #1  Night Activity    02:20  off-hours burst from 192.168.1.50
  #2  Traffic Spike     10:28  flood from 45.33.32.156
  #3  Port Scan         13:58  sequential SYN sweep by 192.168.100.50
  #4  Brute Force       16:27  SSH SYN+RST storm from 192.168.200.1
  #5  Data Exfiltration 19:43  large outbound stream from 192.168.1.25
""")
