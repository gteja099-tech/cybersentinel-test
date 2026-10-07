"""
flow_tracker.py
===============
Reconstructs bidirectional TCP/UDP network flows from raw packet data
and computes the exact 78 CIC-IDS2017-compatible features expected by
the CyberSentinel Random Forest model.

DESIGN PRINCIPLES
-----------------
* No fake values.  Every feature is computed from real packet fields or
  set to 0 when the information is genuinely absent (e.g. bulk stats).
* A "flow" is identified by the 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)
  with bidirectional merging: the smaller-IP side is always "forward".
* Flows are finalized when:
    - A FIN or RST flag is seen, OR
    - The flow has been idle for more than FLOW_TIMEOUT seconds.

WHAT IS COMPUTED HERE vs. WHAT IS NOT
--------------------------------------
Computed from real packets (scapy fields):
  - All packet-count, byte-count, and flag features
  - All IAT (inter-arrival time) features
  - TCP window sizes (Init_Win_bytes_forward/backward)
  - Header lengths
  - PSH/URG/FIN/SYN/RST/ACK flag counts
  - Active/Idle period stats (requires ≥2 flows or gaps > ACTIVITY_TIMEOUT)

NOT computable without deep-inspection or application-layer data:
  - Bulk rates (Fwd/Bwd Avg Bytes/Bulk etc.) — set to 0; CIC-IDS2017
    defines these as TCP segment-level bulk bursts which require tracking
    consecutive PSH-flagged segments; implemented as a best-effort below.

DEPENDENCIES
------------
  pip install scapy
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FLOW_TIMEOUT: float = 120.0       # seconds — finalize idle flows
ACTIVITY_TIMEOUT: float = 5.0     # seconds — gap large enough to be "idle"

# 5-tuple key type
FlowKey = Tuple[str, str, int, int, int]


# ---------------------------------------------------------------------------
# Packet representation (protocol-agnostic)
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """Minimal parsed representation of one captured packet."""
    timestamp: float        # epoch seconds (float, microsecond precision)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int           # 6=TCP, 17=UDP
    ip_header_len: int      # bytes
    tcp_header_len: int     # bytes (0 for UDP)
    payload_len: int        # transport-payload bytes (data after TCP/UDP header)
    total_len: int          # IP total length
    tcp_flags: int          # raw TCP flags byte (0 for UDP)
    tcp_window: int         # TCP window size (0 for UDP)


# ---------------------------------------------------------------------------
# Internal per-direction stats
# ---------------------------------------------------------------------------

@dataclass
class DirectionStats:
    packet_lengths: List[int] = field(default_factory=list)
    header_lengths: List[int] = field(default_factory=list)
    timestamps: List[float]   = field(default_factory=list)
    # TCP flags aggregated across all packets
    flag_counts: Dict[str, int] = field(default_factory=lambda: {
        "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
        "ACK": 0, "URG": 0, "CWE": 0, "ECE": 0,
    })
    tcp_window_first: Optional[int] = None   # window size of first packet
    # Bulk tracking (consecutive PSH segments)
    bulk_bytes: int  = 0
    bulk_pkts: int   = 0
    bulk_count: int  = 0   # number of completed bulk events
    bulk_total_bytes: int = 0
    bulk_total_pkts: int  = 0
    bulk_total_dur: float = 0.0
    _in_bulk: bool  = False
    _bulk_start_ts: float = 0.0

    @property
    def total_bytes(self) -> int:
        return sum(self.packet_lengths)

    @property
    def packet_count(self) -> int:
        return len(self.packet_lengths)


# ---------------------------------------------------------------------------
# TCP flag bitmask constants
# ---------------------------------------------------------------------------

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80   # CWE in CIC naming


# ---------------------------------------------------------------------------
# Flow record
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    key: FlowKey
    start_time: float
    last_seen: float

    fwd: DirectionStats = field(default_factory=DirectionStats)
    bwd: DirectionStats = field(default_factory=DirectionStats)

    # Flow-level IAT (all packets, both directions)
    all_timestamps: List[float] = field(default_factory=list)

    # Active/Idle period tracking
    active_periods: List[float] = field(default_factory=list)
    idle_periods: List[float]   = field(default_factory=list)
    _last_active_start: float   = 0.0
    _last_packet_ts: float      = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_mean(lst: List[float]) -> float:
    return sum(lst) / len(lst) if lst else 0.0

def _safe_std(lst: List[float]) -> float:
    if len(lst) < 2:
        return 0.0
    m = _safe_mean(lst)
    return math.sqrt(sum((x - m) ** 2 for x in lst) / len(lst))

def _safe_max(lst) -> float:
    return max(lst) if lst else 0.0

def _safe_min(lst) -> float:
    return min(lst) if lst else 0.0

def _iat_list(timestamps: List[float]) -> List[float]:
    """Return inter-arrival-time list from a sorted timestamp list."""
    if len(timestamps) < 2:
        return []
    return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

def _flag_set(flags: int, mask: int) -> int:
    return 1 if (flags & mask) else 0


# ---------------------------------------------------------------------------
# Flow Manager
# ---------------------------------------------------------------------------

class FlowTracker:
    """
    Accepts PacketRecord objects one at a time and maintains a dictionary
    of live flows.  Completed flows are moved to `completed_flows`.

    Usage
    -----
        tracker = FlowTracker()
        tracker.add_packet(pkt)           # call for every captured packet
        finished = tracker.flush_expired() # periodically call this
        finished += tracker.finalize_all() # call on shutdown
        for flow_features in finished:
            # flow_features is a dict with the 78 CIC-IDS2017 feature names
            ...
    """

    def __init__(self):
        self._flows: Dict[FlowKey, Flow] = {}
        self.completed_flows: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_packet(self, pkt: PacketRecord) -> None:
        key, is_forward = self._classify(pkt)
        if key not in self._flows:
            self._flows[key] = Flow(
                key=key,
                start_time=pkt.timestamp,
                last_seen=pkt.timestamp,
                _last_active_start=pkt.timestamp,
                _last_packet_ts=pkt.timestamp,
            )
        flow = self._flows[key]
        self._update_flow(flow, pkt, is_forward)

        # Finalize on FIN or RST
        if pkt.protocol == 6 and (pkt.tcp_flags & (FLAG_FIN | FLAG_RST)):
            self._finalize(key)

    def flush_expired(self) -> List[Dict[str, Any]]:
        """Finalize and return flows that have been idle for > FLOW_TIMEOUT."""
        now = time.time()
        expired = [k for k, f in self._flows.items()
                   if (now - f.last_seen) > FLOW_TIMEOUT]
        result = []
        for k in expired:
            feats = self._finalize(k)
            if feats:
                result.append(feats)
        return result

    def finalize_all(self) -> List[Dict[str, Any]]:
        """Finalize every remaining open flow (call on shutdown)."""
        keys = list(self._flows.keys())
        result = []
        for k in keys:
            feats = self._finalize(k)
            if feats:
                result.append(feats)
        return result

    def open_flow_count(self) -> int:
        return len(self._flows)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(pkt: PacketRecord) -> Tuple[FlowKey, bool]:
        """
        Determine the canonical flow key and whether this packet is
        in the forward direction.  Forward = lower IP (lexicographic) or,
        when IPs are equal, lower port.
        """
        if (pkt.src_ip, pkt.src_port) <= (pkt.dst_ip, pkt.dst_port):
            key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
            return key, True
        else:
            key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)
            return key, False

    def _update_flow(self, flow: Flow, pkt: PacketRecord, is_fwd: bool) -> None:
        ts = pkt.timestamp
        direction: DirectionStats = flow.fwd if is_fwd else flow.bwd

        # Active / Idle bookkeeping
        gap = ts - flow._last_packet_ts
        if flow._last_packet_ts > 0:
            if gap > ACTIVITY_TIMEOUT:
                # Record ended active period + idle period
                active_dur = flow._last_packet_ts - flow._last_active_start
                if active_dur > 0:
                    flow.active_periods.append(active_dur)
                flow.idle_periods.append(gap)
                flow._last_active_start = ts
        flow._last_packet_ts = ts
        flow.last_seen = ts

        # Packet length (IP payload = transport header + data)
        pkt_len = pkt.payload_len
        direction.packet_lengths.append(pkt_len)
        direction.timestamps.append(ts)
        flow.all_timestamps.append(ts)

        # Header length
        hdr_len = pkt.ip_header_len + pkt.tcp_header_len
        direction.header_lengths.append(hdr_len)

        # First-packet TCP window
        if direction.tcp_window_first is None and pkt.tcp_window > 0:
            direction.tcp_window_first = pkt.tcp_window

        # TCP flags
        if pkt.protocol == 6:
            f = pkt.tcp_flags
            direction.flag_counts["FIN"] += _flag_set(f, FLAG_FIN)
            direction.flag_counts["SYN"] += _flag_set(f, FLAG_SYN)
            direction.flag_counts["RST"] += _flag_set(f, FLAG_RST)
            direction.flag_counts["PSH"] += _flag_set(f, FLAG_PSH)
            direction.flag_counts["ACK"] += _flag_set(f, FLAG_ACK)
            direction.flag_counts["URG"] += _flag_set(f, FLAG_URG)
            direction.flag_counts["CWE"] += _flag_set(f, FLAG_CWR)
            direction.flag_counts["ECE"] += _flag_set(f, FLAG_ECE)

            # Bulk tracking — a "bulk" is a run of PSH packets
            if f & FLAG_PSH:
                if not direction._in_bulk:
                    direction._in_bulk = True
                    direction._bulk_start_ts = ts
                    direction.bulk_bytes = pkt_len
                    direction.bulk_pkts  = 1
                else:
                    direction.bulk_bytes += pkt_len
                    direction.bulk_pkts  += 1
            else:
                if direction._in_bulk:
                    direction._in_bulk = False
                    direction.bulk_count += 1
                    direction.bulk_total_bytes += direction.bulk_bytes
                    direction.bulk_total_pkts  += direction.bulk_pkts
                    direction.bulk_total_dur   += ts - direction._bulk_start_ts
                    direction.bulk_bytes = 0
                    direction.bulk_pkts  = 0

    def _finalize(self, key: FlowKey) -> Optional[Dict[str, Any]]:
        if key not in self._flows:
            return None
        flow = self._flows.pop(key)

        # Close any open active period
        if flow._last_packet_ts > flow._last_active_start:
            dur = flow._last_packet_ts - flow._last_active_start
            if dur > 0:
                flow.active_periods.append(dur)

        # Close any in-progress bulk
        for direction in (flow.fwd, flow.bwd):
            if direction._in_bulk:
                direction.bulk_count += 1
                direction.bulk_total_bytes += direction.bulk_bytes
                direction.bulk_total_pkts  += direction.bulk_pkts
                direction._in_bulk = False

        feats = self._compute_features(flow)
        self.completed_flows.append(feats)
        return feats

    # ------------------------------------------------------------------
    # Feature computation — maps directly to CIC-IDS2017 column names
    # ------------------------------------------------------------------

    def _compute_features(self, flow: Flow) -> Dict[str, Any]:
        fwd = flow.fwd
        bwd = flow.bwd

        duration_us = (flow.last_seen - flow.start_time) * 1e6   # microseconds
        duration_s  = flow.last_seen - flow.start_time

        # ---- Packet length stats ----
        all_lengths = fwd.packet_lengths + bwd.packet_lengths
        all_lengths_f = [float(x) for x in all_lengths]
        fwd_lengths_f = [float(x) for x in fwd.packet_lengths]
        bwd_lengths_f = [float(x) for x in bwd.packet_lengths]

        pkt_len_mean = _safe_mean(all_lengths_f)
        pkt_len_std  = _safe_std(all_lengths_f)

        # ---- IAT ----
        sorted_all_ts = sorted(flow.all_timestamps)
        flow_iats = _iat_list(sorted_all_ts)
        flow_iats_us = [x * 1e6 for x in flow_iats]

        fwd_iats_us = [x * 1e6 for x in _iat_list(sorted(fwd.timestamps))]
        bwd_iats_us = [x * 1e6 for x in _iat_list(sorted(bwd.timestamps))]

        # ---- Rates ----
        total_fwd_bytes = fwd.total_bytes
        total_bwd_bytes = bwd.total_bytes
        total_bytes = total_fwd_bytes + total_bwd_bytes
        total_pkts  = fwd.packet_count + bwd.packet_count

        flow_bytes_s   = total_bytes  / duration_s if duration_s > 0 else 0.0
        flow_pkts_s    = total_pkts   / duration_s if duration_s > 0 else 0.0
        fwd_pkts_s     = fwd.packet_count / duration_s if duration_s > 0 else 0.0
        bwd_pkts_s     = bwd.packet_count / duration_s if duration_s > 0 else 0.0

        # ---- Header lengths ----
        fwd_hdr_total = sum(fwd.header_lengths)
        bwd_hdr_total = sum(bwd.header_lengths)

        # ---- Segment sizes (= avg payload per packet) ----
        avg_fwd_seg = _safe_mean(fwd_lengths_f)
        avg_bwd_seg = _safe_mean(bwd_lengths_f)
        avg_pkt_size = _safe_mean(all_lengths_f)

        # ---- Down/Up ratio ----
        down_up = bwd.total_bytes / fwd.total_bytes if fwd.total_bytes > 0 else 0.0

        # ---- Bulk features ----
        def bulk_avg_bytes(d: DirectionStats) -> float:
            return d.bulk_total_bytes / d.bulk_count if d.bulk_count > 0 else 0.0
        def bulk_avg_pkts(d: DirectionStats) -> float:
            return d.bulk_total_pkts / d.bulk_count if d.bulk_count > 0 else 0.0
        def bulk_avg_rate(d: DirectionStats) -> float:
            return d.bulk_total_bytes / d.bulk_total_dur if d.bulk_total_dur > 0 else 0.0

        # ---- Active / Idle ----
        act = [x * 1e6 for x in flow.active_periods]  # convert to µs
        idl = [x * 1e6 for x in flow.idle_periods]

        # ---- Subflow (approximation: 1 subflow = entire flow) ----
        subflow_fwd_pkts  = fwd.packet_count
        subflow_fwd_bytes = total_fwd_bytes
        subflow_bwd_pkts  = bwd.packet_count
        subflow_bwd_bytes = total_bwd_bytes

        # ---- act_data_pkt_fwd (fwd packets that carry actual data) ----
        act_data_pkt_fwd = sum(1 for l in fwd.packet_lengths if l > 0)

        # ---- min_seg_size_forward ----
        min_seg_fwd = min(fwd.packet_lengths) if fwd.packet_lengths else 0

        # ---- Destination port ----
        _, _, _, dst_port, _ = flow.key

        # ---- Compose the dict in the EXACT order of feature_columns.pkl ----
        return {
            "Destination Port":              dst_port,
            "Flow Duration":                 duration_us,
            "Total Fwd Packets":             fwd.packet_count,
            "Total Backward Packets":        bwd.packet_count,
            "Total Length of Fwd Packets":   total_fwd_bytes,
            "Total Length of Bwd Packets":   total_bwd_bytes,
            "Fwd Packet Length Max":         _safe_max(fwd_lengths_f),
            "Fwd Packet Length Min":         _safe_min(fwd_lengths_f),
            "Fwd Packet Length Mean":        _safe_mean(fwd_lengths_f),
            "Fwd Packet Length Std":         _safe_std(fwd_lengths_f),
            "Bwd Packet Length Max":         _safe_max(bwd_lengths_f),
            "Bwd Packet Length Min":         _safe_min(bwd_lengths_f),
            "Bwd Packet Length Mean":        _safe_mean(bwd_lengths_f),
            "Bwd Packet Length Std":         _safe_std(bwd_lengths_f),
            "Flow Bytes/s":                  flow_bytes_s,
            "Flow Packets/s":                flow_pkts_s,
            "Flow IAT Mean":                 _safe_mean(flow_iats_us),
            "Flow IAT Std":                  _safe_std(flow_iats_us),
            "Flow IAT Max":                  _safe_max(flow_iats_us),
            "Flow IAT Min":                  _safe_min(flow_iats_us),
            "Fwd IAT Total":                 sum(fwd_iats_us),
            "Fwd IAT Mean":                  _safe_mean(fwd_iats_us),
            "Fwd IAT Std":                   _safe_std(fwd_iats_us),
            "Fwd IAT Max":                   _safe_max(fwd_iats_us),
            "Fwd IAT Min":                   _safe_min(fwd_iats_us),
            "Bwd IAT Total":                 sum(bwd_iats_us),
            "Bwd IAT Mean":                  _safe_mean(bwd_iats_us),
            "Bwd IAT Std":                   _safe_std(bwd_iats_us),
            "Bwd IAT Max":                   _safe_max(bwd_iats_us),
            "Bwd IAT Min":                   _safe_min(bwd_iats_us),
            "Fwd PSH Flags":                 fwd.flag_counts["PSH"],
            "Bwd PSH Flags":                 bwd.flag_counts["PSH"],
            "Fwd URG Flags":                 fwd.flag_counts["URG"],
            "Bwd URG Flags":                 bwd.flag_counts["URG"],
            "Fwd Header Length":             fwd_hdr_total,
            "Bwd Header Length":             bwd_hdr_total,
            "Fwd Packets/s":                 fwd_pkts_s,
            "Bwd Packets/s":                 bwd_pkts_s,
            "Min Packet Length":             _safe_min(all_lengths_f),
            "Max Packet Length":             _safe_max(all_lengths_f),
            "Packet Length Mean":            pkt_len_mean,
            "Packet Length Std":             pkt_len_std,
            "Packet Length Variance":        pkt_len_std ** 2,
            "FIN Flag Count":                fwd.flag_counts["FIN"] + bwd.flag_counts["FIN"],
            "SYN Flag Count":                fwd.flag_counts["SYN"] + bwd.flag_counts["SYN"],
            "RST Flag Count":                fwd.flag_counts["RST"] + bwd.flag_counts["RST"],
            "PSH Flag Count":                fwd.flag_counts["PSH"] + bwd.flag_counts["PSH"],
            "ACK Flag Count":                fwd.flag_counts["ACK"] + bwd.flag_counts["ACK"],
            "URG Flag Count":                fwd.flag_counts["URG"] + bwd.flag_counts["URG"],
            "CWE Flag Count":                fwd.flag_counts["CWE"] + bwd.flag_counts["CWE"],
            "ECE Flag Count":                fwd.flag_counts["ECE"] + bwd.flag_counts["ECE"],
            "Down/Up Ratio":                 down_up,
            "Average Packet Size":           avg_pkt_size,
            "Avg Fwd Segment Size":          avg_fwd_seg,
            "Avg Bwd Segment Size":          avg_bwd_seg,
            "Fwd Header Length.1":           fwd_hdr_total,          # duplicate col in CIC
            "Fwd Avg Bytes/Bulk":            bulk_avg_bytes(fwd),
            "Fwd Avg Packets/Bulk":          bulk_avg_pkts(fwd),
            "Fwd Avg Bulk Rate":             bulk_avg_rate(fwd),
            "Bwd Avg Bytes/Bulk":            bulk_avg_bytes(bwd),
            "Bwd Avg Packets/Bulk":          bulk_avg_pkts(bwd),
            "Bwd Avg Bulk Rate":             bulk_avg_rate(bwd),
            "Subflow Fwd Packets":           subflow_fwd_pkts,
            "Subflow Fwd Bytes":             subflow_fwd_bytes,
            "Subflow Bwd Packets":           subflow_bwd_pkts,
            "Subflow Bwd Bytes":             subflow_bwd_bytes,
            "Init_Win_bytes_forward":        fwd.tcp_window_first or 0,
            "Init_Win_bytes_backward":       bwd.tcp_window_first or 0,
            "act_data_pkt_fwd":              act_data_pkt_fwd,
            "min_seg_size_forward":          min_seg_fwd,
            "Active Mean":                   _safe_mean(act),
            "Active Std":                    _safe_std(act),
            "Active Max":                    _safe_max(act),
            "Active Min":                    _safe_min(act),
            "Idle Mean":                     _safe_mean(idl),
            "Idle Std":                      _safe_std(idl),
            "Idle Max":                      _safe_max(idl),
            "Idle Min":                      _safe_min(idl),
        }
