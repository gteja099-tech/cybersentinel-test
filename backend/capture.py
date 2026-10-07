"""
capture.py
==========
Live packet capture for the CyberSentinel Test Website.

Captures TCP packets on the macOS loopback interface (lo0) using tcpdump
in raw mode, parses them with scapy, hands them to FlowTracker, and
periodically emits completed flows with their 78 CIC-IDS2017 features.

HOW IT WORKS
------------
1. Spawns `sudo tcpdump` as a subprocess writing raw pcap to stdout.
2. Scapy's PcapReader reads the binary stream and yields Packet objects.
3. Each packet is converted to a PacketRecord and fed to FlowTracker.
4. Every FLUSH_INTERVAL seconds, expired flows are emitted.
5. Each emitted flow's features are validated against feature_columns.pkl.
6. Validated feature vectors are stored in a thread-safe queue
   (FLOW_QUEUE) so that the FastAPI server can serve them via
   GET /api/flow-features without blocking the capture loop.

RUNNING
-------
This script must run as root (or with appropriate sudo rights) because
tcpdump requires raw-socket access.

    sudo python3 capture.py

WHAT THIS DOES NOT DO
---------------------
- It does NOT call the ML model.
- It does NOT generate fake features.
- It does NOT post-process or normalise features (that is the ML layer's job).

INTEGRATION POINT
-----------------
When the ML layer is ready, import FLOW_QUEUE from this module and
consume feature dicts from it.
"""

import json
import os
import pickle
import queue
import subprocess
import sys
import threading
import time
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Guard: scapy must be installed
# ---------------------------------------------------------------------------
try:
    from scapy.all import IP, TCP, UDP, rdpcap, sniff  # noqa: F401
    from scapy.layers.inet import IP as ScapyIP, TCP as ScapyTCP, UDP as ScapyUDP
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from flow_tracker import FlowTracker, PacketRecord

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BACKEND_DIR  = Path(__file__).parent
FEATURE_COLS = BACKEND_DIR / "feature_columns.pkl"

# ---------------------------------------------------------------------------
# Load feature columns
# ---------------------------------------------------------------------------

def load_feature_columns() -> List[str]:
    with open(FEATURE_COLS, "rb") as f:
        cols = pickle.load(f)
    assert len(cols) == 78, f"Expected 78 features, got {len(cols)}"
    return list(cols)

FEATURE_COLUMNS: List[str] = load_feature_columns()

# ---------------------------------------------------------------------------
# Shared flow queue (thread-safe)
# ---------------------------------------------------------------------------

FLOW_QUEUE: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=2000)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INTERFACE       = "lo0"          # macOS loopback
BPF_FILTER      = "tcp port 8000 or udp port 8000"
FLUSH_INTERVAL  = 5.0            # seconds between expired-flow checks
TCPDUMP_PATH    = "/usr/sbin/tcpdump"

# ---------------------------------------------------------------------------
# Packet parser
# ---------------------------------------------------------------------------

def _parse_scapy_packet(pkt) -> Optional[PacketRecord]:
    """Convert a scapy Packet to a PacketRecord. Returns None if not IP/TCP/UDP."""
    if not pkt.haslayer(ScapyIP):
        return None
    ip = pkt[ScapyIP]
    proto = ip.proto  # 6=TCP, 17=UDP
    if proto not in (6, 17):
        return None

    src_ip  = ip.src
    dst_ip  = ip.dst
    ip_hlen = ip.ihl * 4  # IHL field is in 32-bit words

    if proto == 6 and pkt.haslayer(ScapyTCP):
        tcp = pkt[ScapyTCP]
        src_port    = tcp.sport
        dst_port    = tcp.dport
        tcp_hlen    = tcp.dataofs * 4
        tcp_flags   = int(tcp.flags)
        tcp_window  = tcp.window
        payload_len = max(0, ip.len - ip_hlen - tcp_hlen)
    elif proto == 17 and pkt.haslayer(ScapyUDP):
        udp = pkt[ScapyUDP]
        src_port    = udp.sport
        dst_port    = udp.dport
        tcp_hlen    = 8   # UDP header is always 8 bytes
        tcp_flags   = 0
        tcp_window  = 0
        payload_len = max(0, udp.len - 8)
    else:
        return None

    # Use scapy's packet timestamp (set by libpcap from the kernel)
    ts = float(pkt.time)

    return PacketRecord(
        timestamp    = ts,
        src_ip       = src_ip,
        dst_ip       = dst_ip,
        src_port     = src_port,
        dst_port     = dst_port,
        protocol     = proto,
        ip_header_len= ip_hlen,
        tcp_header_len=tcp_hlen,
        payload_len  = payload_len,
        total_len    = ip.len,
        tcp_flags    = tcp_flags,
        tcp_window   = tcp_window,
    )


# ---------------------------------------------------------------------------
# Feature vector validation
# ---------------------------------------------------------------------------

def validate_feature_vector(feat_dict: Dict[str, Any]) -> bool:
    """
    Returns True only if feat_dict contains exactly the 78 expected keys
    in the correct positions.  Logs any mismatch to stderr.
    """
    actual_keys = list(feat_dict.keys())
    if actual_keys != FEATURE_COLUMNS:
        missing   = set(FEATURE_COLUMNS) - set(actual_keys)
        extra     = set(actual_keys) - set(FEATURE_COLUMNS)
        print(f"[VALIDATE] Feature mismatch. Missing={missing}, Extra={extra}",
              file=sys.stderr)
        return False
    return True


# ---------------------------------------------------------------------------
# Capture loop
# ---------------------------------------------------------------------------

def _capture_loop(tracker: FlowTracker, stop_event: threading.Event) -> None:
    """
    Spawns tcpdump and feeds packets to FlowTracker via scapy's PcapReader.
    Runs in its own thread.
    """
    if not SCAPY_AVAILABLE:
        print("[capture] ERROR: scapy is not installed. "
              "Run: pip install scapy", file=sys.stderr)
        return

    cmd = [
        TCPDUMP_PATH,
        "-i", INTERFACE,
        "-nn",               # no name resolution
        "-s", "0",           # full packet capture
        "-w", "-",           # write raw pcap to stdout
        BPF_FILTER,
    ]

    print(f"[capture] Starting: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        print(f"[capture] tcpdump not found at {TCPDUMP_PATH}", file=sys.stderr)
        return
    except PermissionError:
        print("[capture] Permission denied. Run as root / with sudo.", file=sys.stderr)
        return

    print(f"[capture] tcpdump PID={proc.pid}  interface={INTERFACE}  "
          f"filter='{BPF_FILTER}'")

    try:
        reader = PcapReader(proc.stdout)
        next_flush = time.monotonic() + FLUSH_INTERVAL

        for raw_pkt in reader:
            if stop_event.is_set():
                break

            pkt_rec = _parse_scapy_packet(raw_pkt)
            if pkt_rec:
                tracker.add_packet(pkt_rec)

            # Periodically flush expired flows
            now = time.monotonic()
            if now >= next_flush:
                next_flush = now + FLUSH_INTERVAL
                _emit_flows(tracker.flush_expired())

    except Exception as exc:
        print(f"[capture] Error in capture loop: {exc}", file=sys.stderr)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[capture] tcpdump stopped.")


import urllib.request
import urllib.error

def _emit_flows(flows: List[Dict[str, Any]]) -> None:
    """Validate and push completed flow feature dicts to FastAPI via HTTP POST."""
    for feat in flows:
        if not validate_feature_vector(feat):
            print("[capture] Skipping invalid feature vector.", file=sys.stderr)
            continue
            
        print(f"[capture] Flow emitted → dest_port={feat.get('Destination Port')}  "
              f"pkts={int(feat.get('Total Fwd Packets', 0))+int(feat.get('Total Backward Packets', 0))}  "
              f"duration_µs={feat.get('Flow Duration', 0):.0f}")
              
        try:
            req = urllib.request.Request(
                url="http://127.0.0.1:8000/api/ingest-flow",
                data=json.dumps(feat).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as response:
                if response.status == 200:
                    print("[capture] Sent flow to FastAPI successfully")
                else:
                    print(f"[capture] Failed to send flow to FastAPI: HTTP {response.status}", file=sys.stderr)
        except Exception as e:
            print(f"[capture] Failed to send flow to FastAPI: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Public API: start / stop capture thread
# ---------------------------------------------------------------------------

_capture_thread: Optional[threading.Thread] = None
_stop_event     = threading.Event()
_tracker        = FlowTracker()


def start_capture() -> None:
    """Start the background capture thread (non-blocking)."""
    global _capture_thread
    if _capture_thread and _capture_thread.is_alive():
        print("[capture] Already running.")
        return
    _stop_event.clear()
    _capture_thread = threading.Thread(
        target=_capture_loop,
        args=(_tracker, _stop_event),
        daemon=True,
        name="CaptureThread",
    )
    _capture_thread.start()
    print(f"[capture] Thread started: {_capture_thread.name}")


def stop_capture() -> List[Dict[str, Any]]:
    """Stop capture and return any remaining open flows."""
    _stop_event.set()
    if _capture_thread:
        _capture_thread.join(timeout=5)
    remaining = _tracker.finalize_all()
    _emit_flows(remaining)
    return remaining


def get_queued_flows(max_count: int = 100) -> List[Dict[str, Any]]:
    """
    Drain up to max_count items from FLOW_QUEUE without blocking.
    Called by the FastAPI endpoint GET /api/flow-features.
    """
    result = []
    for _ in range(max_count):
        try:
            result.append(FLOW_QUEUE.get_nowait())
        except queue.Empty:
            break
    return result


def get_open_flow_count() -> int:
    return _tracker.open_flow_count()


# ---------------------------------------------------------------------------
# Standalone run (for testing outside FastAPI)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("CyberSentinel — Traffic Capture & Feature Extraction")
    print("=" * 70)
    print(f"\nFeature columns loaded: {len(FEATURE_COLUMNS)}")
    for i, name in enumerate(FEATURE_COLUMNS, 1):
        print(f"  {i:3d}. {name}")
    print()
    print("Starting capture on lo0 port 8000 ...")
    print("Press Ctrl+C to stop.\n")

    start_capture()
    try:
        while True:
            time.sleep(2)
            flows = get_queued_flows()
            if flows:
                print(f"\n[main] {len(flows)} flow(s) ready:")
                for f in flows:
                    print(json.dumps(f, indent=2))
            else:
                print(f"[main] Open flows: {get_open_flow_count()}  "
                      f"Queued: {FLOW_QUEUE.qsize()}", end="\r")
    except KeyboardInterrupt:
        print("\n[main] Stopping...")
        remaining = stop_capture()
        if remaining:
            print(f"[main] Final flows from open connections: {len(remaining)}")
            for f in remaining:
                print(json.dumps(f, indent=2))
        print("[main] Done.")
