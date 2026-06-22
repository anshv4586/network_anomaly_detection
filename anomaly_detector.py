#!/usr/bin/env python3
"""
Network Anomaly Detection System
---------------------------------
Reads a CSV-formatted network log and detects:
  • Traffic spikes        (Z-score on 5-min byte totals)
  • Port scans            (many distinct ports from one IP in 5 min)
  • Brute-force attempts  (many failed connections from one IP in 5 min)
  • Off-hours activity    (unusual connection count during 00:00-06:00)
  • Data exfiltration     (sustained abnormally-large outbound transfers)

Usage:
  python anomaly_detector.py [log_file]   (default: sample_logs/network_traffic.log)
"""

import sys
import os
from collections import defaultdict

import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches

# ---------------------------------------------------------------------------
# Tuneable thresholds
# ---------------------------------------------------------------------------
Z_SCORE_THRESHOLD      = 2.5   # σ above mean → traffic spike
MIN_SCAN_PORTS         = 15    # distinct ports in 5 min → port scan
MIN_BRUTE_ATTEMPTS     = 10    # failed connections in 5 min → brute force
NIGHT_HOURS            = set(range(0, 6))   # 00:00–05:59 = off-hours
NIGHT_MIN_CONNECTIONS  = 20    # connections per 30-min window to flag
EXFIL_Z_THRESHOLD      = 5.5   # σ on rolling 3-window mean → exfiltration

ANOMALY_COLORS = {
    "Traffic Spike":      "#E53935",
    "Port Scan":          "#FB8C00",
    "Brute Force":        "#8E24AA",
    "Night Activity":     "#1E88E5",
    "Data Exfiltration":  "#6D4C41",
}

SEVERITY_PREFIX = {
    "CRITICAL": "[!!!]",
    "HIGH":     "[!! ]",
    "MEDIUM":   "[!  ]",
    "LOW":      "[.  ]",
}


# ---------------------------------------------------------------------------
# Log loading
# ---------------------------------------------------------------------------

def load_log(filepath: str) -> pd.DataFrame:
    if not os.path.exists(filepath):
        sys.exit(f"[-] Log file not found: {filepath}\n"
                 "    Run generate_sample_log.py first.")
    df = pd.read_csv(filepath, parse_dates=["timestamp"])
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"[+] Loaded {len(df):,} entries  |  "
          f"{df['timestamp'].min().strftime('%Y-%m-%d %H:%M')} – "
          f"{df['timestamp'].max().strftime('%H:%M')}")
    return df


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def detect_traffic_spikes(df: pd.DataFrame) -> list:
    anomalies = []
    series = df.set_index("timestamp")["bytes"].resample("5min").sum()
    mean, std = series.mean(), series.std()
    if std == 0:
        return anomalies
    for t, val in series.items():
        z = (val - mean) / std
        if z > Z_SCORE_THRESHOLD:
            anomalies.append({
                "timestamp": t,
                "type": "Traffic Spike",
                "severity": "CRITICAL" if z > 6 else "HIGH",
                "detail": (f"Traffic {z:.1f}σ above normal — "
                           f"{val/1024:.0f} KB in 5-min window"),
            })
    return anomalies


def detect_port_scans(df: pd.DataFrame) -> list:
    anomalies = []
    tmp = df.copy()
    tmp["bucket"] = tmp["timestamp"].dt.floor("5min")
    for (bucket, src), grp in tmp.groupby(["bucket", "src_ip"]):
        unique_ports = grp["dst_port"].nunique()
        if unique_ports >= MIN_SCAN_PORTS:
            anomalies.append({
                "timestamp": bucket,
                "type": "Port Scan",
                "severity": "HIGH",
                "detail": (f"{src} probed {unique_ports} distinct ports "
                           f"in 5-min window"),
            })
    return anomalies


def detect_brute_force(df: pd.DataFrame) -> list:
    anomalies = []
    tmp = df[df["status"] == "FAILED"].copy()
    tmp["bucket"] = tmp["timestamp"].dt.floor("5min")
    for (bucket, src), grp in tmp.groupby(["bucket", "src_ip"]):
        if len(grp) >= MIN_BRUTE_ATTEMPTS:
            target = grp["dst_ip"].mode()[0]
            port   = grp["dst_port"].mode()[0]
            anomalies.append({
                "timestamp": bucket,
                "type": "Brute Force",
                "severity": "HIGH",
                "detail": (f"{src} → {target}:{port}  "
                           f"{len(grp)} failed attempts in 5-min window"),
            })
    return anomalies


def detect_night_activity(df: pd.DataFrame) -> list:
    anomalies = []
    tmp = df.copy()
    tmp["hour"]   = tmp["timestamp"].dt.hour
    tmp["bucket"] = tmp["timestamp"].dt.floor("30min")
    night = tmp[tmp["hour"].isin(NIGHT_HOURS)]
    for bucket, grp in night.groupby("bucket"):
        if len(grp) >= NIGHT_MIN_CONNECTIONS:
            top_src = grp["src_ip"].mode()[0]
            anomalies.append({
                "timestamp": bucket,
                "type": "Night Activity",
                "severity": "MEDIUM",
                "detail": (f"{len(grp)} connections during off-hours "
                           f"({bucket.strftime('%H:%M')})  "
                           f"top source: {top_src}"),
            })
    return anomalies


def detect_data_exfiltration(df: pd.DataFrame) -> list:
    anomalies = []
    series = df.set_index("timestamp")["bytes"].resample("5min").sum()
    mean, std = series.mean(), series.std()
    if std == 0:
        return anomalies
    rolling = series.rolling(3, min_periods=1).mean()
    for t, val in rolling.items():
        z = (val - mean) / std
        if z > EXFIL_Z_THRESHOLD:
            anomalies.append({
                "timestamp": t,
                "type": "Data Exfiltration",
                "severity": "CRITICAL",
                "detail": (f"Sustained outbound {val/1_048_576:.1f} MB "
                           f"(rolling avg {z:.1f}σ above baseline)"),
            })
    return anomalies


# ---------------------------------------------------------------------------
# Deduplication helper
# ---------------------------------------------------------------------------

def deduplicate(anomalies: list, gap_minutes: int = 10) -> list:
    """Collapse same-type anomalies within `gap_minutes` into one entry."""
    by_type: dict[str, list] = defaultdict(list)
    for a in sorted(anomalies, key=lambda x: x["timestamp"]):
        by_type[a["type"]].append(a)

    result = []
    for atype, group in by_type.items():
        merged = [group[0]]
        for curr in group[1:]:
            prev = merged[-1]
            delta = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 60
            if delta > gap_minutes:
                merged.append(curr)
            # keep the highest severity of the merged window
            elif curr["severity"] == "CRITICAL":
                merged[-1] = curr
        result.extend(merged)
    return sorted(result, key=lambda x: x["timestamp"])


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(anomalies: list) -> None:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    print("\n" + "=" * 72)
    print("  ANOMALY DETECTION REPORT")
    print("=" * 72)

    if not anomalies:
        print("  No anomalies detected.")
        print("=" * 72)
        return

    sorted_a = sorted(anomalies, key=lambda x: (sev_order.get(x["severity"], 9),
                                                  x["timestamp"]))
    for i, a in enumerate(sorted_a, 1):
        prefix = SEVERITY_PREFIX.get(a["severity"], "[   ]")
        print(f"\n  #{i:02d}  {prefix}  {a['severity']}")
        print(f"        Type      : {a['type']}")
        print(f"        Time      : {a['timestamp'].strftime('%Y-%m-%d  %H:%M:%S')}")
        print(f"        Detail    : {a['detail']}")

    print("\n" + "-" * 72)
    print(f"  Total anomalies detected : {len(anomalies)}")
    counts: dict[str, int] = defaultdict(int)
    for a in anomalies:
        counts[a["type"]] += 1
    for t, c in sorted(counts.items()):
        print(f"    • {t:<22} {c}")
    print("=" * 72 + "\n")


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def plot(df: pd.DataFrame, anomalies: list, out_path: str = "anomaly_report.png") -> None:
    fig, axes = plt.subplots(3, 1, figsize=(17, 11), sharex=True,
                             gridspec_kw={"height_ratios": [2, 1.2, 1]})
    fig.patch.set_facecolor("#F7F9FC")
    fig.suptitle("Network Anomaly Detection — 2024-01-15",
                 fontsize=15, fontweight="bold", y=0.99)

    ts_idx = df.set_index("timestamp")

    # 5-minute resampled series
    kb       = ts_idx["bytes"].resample("5min").sum() / 1024
    conns    = ts_idx["bytes"].resample("5min").count()
    failed   = (ts_idx[ts_idx["status"] == "FAILED"]["status"]
                .resample("5min").count())

    # ---- Panel 1: traffic volume ----
    ax1 = axes[0]
    ax1.set_facecolor("#EEF2F7")
    ax1.fill_between(kb.index, kb.values, alpha=0.35, color="#1565C0")
    ax1.plot(kb.index, kb.values, color="#1565C0", linewidth=1.1)
    ax1.set_ylabel("Traffic (KB / 5 min)", fontsize=9)
    ax1.set_title("Network Traffic Volume", fontsize=10, loc="left", pad=4)
    ax1.grid(True, alpha=0.25, linestyle="--")

    # ---- Panel 2: connection count ----
    ax2 = axes[1]
    ax2.set_facecolor("#EEF2F7")
    ax2.fill_between(conns.index, conns.values, alpha=0.35, color="#2E7D32")
    ax2.plot(conns.index, conns.values, color="#2E7D32", linewidth=1.1)
    ax2.set_ylabel("Connections / 5 min", fontsize=9)
    ax2.set_title("Connection Count", fontsize=10, loc="left", pad=4)
    ax2.grid(True, alpha=0.25, linestyle="--")

    # ---- Panel 3: failed connections ----
    ax3 = axes[2]
    ax3.set_facecolor("#EEF2F7")
    ax3.bar(failed.index, failed.values,
            width=pd.Timedelta("4min"), color="#C62828", alpha=0.75)
    ax3.set_ylabel("Failed / 5 min", fontsize=9)
    ax3.set_title("Failed Connections", fontsize=10, loc="left", pad=4)
    ax3.grid(True, alpha=0.25, linestyle="--")

    # ---- Anomaly markers ----
    legend_handles: dict[str, mpatches.Patch] = {}
    label_y_offset: dict[str, float] = {}   # avoid label collisions per panel

    for a in anomalies:
        color = ANOMALY_COLORS.get(a["type"], "#FF0000")
        atype = a["type"]
        t = a["timestamp"]

        for ax in axes:
            ax.axvline(t, color=color, linestyle="--", linewidth=1.6, alpha=0.85)

        # Annotation on panel 1 — stagger vertically if types overlap
        ymax = float(kb.max()) if kb.max() > 0 else 1.0
        base_frac = 0.92
        used_frac = label_y_offset.get(atype, base_frac)
        label_y_offset[atype] = max(used_frac - 0.12, 0.55)

        short = atype.replace(" ", "\n")
        ax1.annotate(
            short,
            xy=(t, ymax * used_frac),
            fontsize=7, color=color, ha="center", fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.25", fc="white",
                      ec=color, alpha=0.9, linewidth=1),
        )

        if atype not in legend_handles:
            legend_handles[atype] = mpatches.Patch(color=color, label=atype)

    # ---- X-axis formatting ----
    ax3.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax3.xaxis.set_major_locator(mdates.HourLocator(interval=2))
    plt.setp(ax3.xaxis.get_majorticklabels(), rotation=40, ha="right", fontsize=8)
    ax3.set_xlabel("Time (UTC)", fontsize=9)

    # ---- Legend ----
    if legend_handles:
        fig.legend(
            handles=list(legend_handles.values()),
            loc="lower center",
            ncol=len(legend_handles),
            bbox_to_anchor=(0.5, 0.005),
            fontsize=9,
            framealpha=0.9,
            title="Detected Anomaly Types",
            title_fontsize=9,
        )

    plt.tight_layout(rect=[0, 0.055, 1, 0.97])
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"[+] Graph saved → {out_path}")
    plt.show()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/network_traffic.log"

    print("=" * 60)
    print("  NETWORK ANOMALY DETECTION SYSTEM")
    print("=" * 60)
    print(f"  Log : {log_file}")
    print("=" * 60)

    df = load_log(log_file)

    print("\n[*] Running detectors ...")
    raw_anomalies: list = []
    detectors = [
        ("Traffic Spike",      detect_traffic_spikes),
        ("Port Scan",          detect_port_scans),
        ("Brute Force",        detect_brute_force),
        ("Night Activity",     detect_night_activity),
        ("Data Exfiltration",  detect_data_exfiltration),
    ]
    for label, fn in detectors:
        found = fn(df.copy())
        status = f"{len(found)} window(s)" if found else "clean"
        print(f"    {label:<22} : {status}")
        raw_anomalies.extend(found)

    anomalies = deduplicate(raw_anomalies)
    print_report(anomalies)
    plot(df, anomalies)


if __name__ == "__main__":
    main()
