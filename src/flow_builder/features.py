"""
File: src/flow_builder/features.py

Feature extraction from flows
Computes CIC-IDS2018 style features
"""

import statistics
import numpy as np
from typing import Dict, List, Tuple

from .flow import Flow
from ..core.kernel_panel import PacketRecordV1


# ============ FEATURE COLUMNS (FIXED ORDER) ============

FEATURE_COLUMNS = [
    # Duration
    'flow_duration',
    
    # Packet counts
    'num_forward_packets',
    'num_backward_packets',
    'num_forward_bytes',
    'num_backward_bytes',
    
    # Forward packet length stats
    'fwd_packet_len_min',
    'fwd_packet_len_max',
    'fwd_packet_len_mean',
    'fwd_packet_len_std',
    
    # Backward packet length stats
    'bwd_packet_len_min',
    'bwd_packet_len_max',
    'bwd_packet_len_mean',
    'bwd_packet_len_std',
    
    # Forward IAT (Inter-Arrival Time)
    'fwd_iat_min',
    'fwd_iat_max',
    'fwd_iat_mean',
    'fwd_iat_std',
    
    # Backward IAT
    'bwd_iat_min',
    'bwd_iat_max',
    'bwd_iat_mean',
    'bwd_iat_std',
    
    # TCP Flags
    'syn_count',
    'ack_count',
    'fin_count',
    'rst_count',
    'psh_count',
    'urg_count',
    'cwr_count',
    'ece_count',
    
    # Total packets stats
    'total_packet_len_min',
    'total_packet_len_max',
    'total_packet_len_mean',
    'total_packet_len_std',
    
    # Total IAT
    'total_iat_min',
    'total_iat_max',
    'total_iat_mean',
    'total_iat_std',
    
    # Advanced
    'fwd_packets_per_second',
    'bwd_packets_per_second',
    'flow_packets_per_second',
    'flow_bytes_per_second',
    
    # Protocol specific
    'protocol_type',
    'direction_value',
    'source_port_entropy',
    'dest_port_entropy',
    
    # Additional
    'avg_fwd_segment_size',
    'avg_bwd_segment_size',
    'fwd_bulk_rate',
    'bwd_bulk_rate',
]

assert len(FEATURE_COLUMNS) == 48, f"Expected 48 features, got {len(FEATURE_COLUMNS)}"


class FeatureBuilder:
    """Extract features from a Flow"""
    
    @staticmethod
    def build_features(flow: Flow) -> Dict[str, float]:
        """
        Build feature dictionary from flow.
        
        Args:
            flow: Flow object with packets
        
        Returns:
            Dictionary with all feature values (keys = FEATURE_COLUMNS)
        """
        
        features = {}
        
        # ============ DURATION ============
        duration_sec = flow.get_duration_seconds()
        if duration_sec == 0:
            duration_sec = 0.001  # Avoid division by zero
        features['flow_duration'] = duration_sec
        
        # ============ PACKET COUNTS ============
        fwd_packets = flow.forward_packets
        bwd_packets = flow.backward_packets
        
        features['num_forward_packets'] = float(len(fwd_packets))
        features['num_backward_packets'] = float(len(bwd_packets))
        features['num_forward_bytes'] = float(sum(p.captured_len for p in fwd_packets))
        features['num_backward_bytes'] = float(sum(p.captured_len for p in bwd_packets))
        
        # ============ LENGTH STATISTICS ============
        fwd_len_stats = FeatureBuilder._compute_len_stats(fwd_packets)
        features['fwd_packet_len_min'] = fwd_len_stats['min']
        features['fwd_packet_len_max'] = fwd_len_stats['max']
        features['fwd_packet_len_mean'] = fwd_len_stats['mean']
        features['fwd_packet_len_std'] = fwd_len_stats['std']
        
        bwd_len_stats = FeatureBuilder._compute_len_stats(bwd_packets)
        features['bwd_packet_len_min'] = bwd_len_stats['min']
        features['bwd_packet_len_max'] = bwd_len_stats['max']
        features['bwd_packet_len_mean'] = bwd_len_stats['mean']
        features['bwd_packet_len_std'] = bwd_len_stats['std']
        
        # ============ INTER-ARRIVAL TIME (IAT) ============
        fwd_iat_stats = FeatureBuilder._compute_iat_stats(fwd_packets)
        features['fwd_iat_min'] = fwd_iat_stats['min']
        features['fwd_iat_max'] = fwd_iat_stats['max']
        features['fwd_iat_mean'] = fwd_iat_stats['mean']
        features['fwd_iat_std'] = fwd_iat_stats['std']
        
        bwd_iat_stats = FeatureBuilder._compute_iat_stats(bwd_packets)
        features['bwd_iat_min'] = bwd_iat_stats['min']
        features['bwd_iat_max'] = bwd_iat_stats['max']
        features['bwd_iat_mean'] = bwd_iat_stats['mean']
        features['bwd_iat_std'] = bwd_iat_stats['std']
        
        # ============ TCP FLAGS ============
        # TCP flags: 0x02=SYN, 0x10=ACK, 0x01=FIN, 0x04=RST, 0x08=PSH, 0x20=URG, 0x80=CWR, 0x40=ECE
        features['syn_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x02))
        features['ack_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x10))
        features['fin_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x01))
        features['rst_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x04))
        features['psh_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x08))
        features['urg_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x20))
        features['cwr_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x80))
        features['ece_count'] = float(FeatureBuilder._count_tcp_flag(flow.packets, 0x40))
        
        # ============ TOTAL PACKET LENGTH STATS ============
        total_len_stats = FeatureBuilder._compute_len_stats(flow.packets)
        features['total_packet_len_min'] = total_len_stats['min']
        features['total_packet_len_max'] = total_len_stats['max']
        features['total_packet_len_mean'] = total_len_stats['mean']
        features['total_packet_len_std'] = total_len_stats['std']
        
        # ============ TOTAL IAT ============
        total_iat_stats = FeatureBuilder._compute_iat_stats(flow.packets)
        features['total_iat_min'] = total_iat_stats['min']
        features['total_iat_max'] = total_iat_stats['max']
        features['total_iat_mean'] = total_iat_stats['mean']
        features['total_iat_std'] = total_iat_stats['std']
        
        # ============ RATE FEATURES ============
        features['fwd_packets_per_second'] = len(fwd_packets) / duration_sec if duration_sec > 0 else 0
        features['bwd_packets_per_second'] = len(bwd_packets) / duration_sec if duration_sec > 0 else 0
        features['flow_packets_per_second'] = len(flow.packets) / duration_sec if duration_sec > 0 else 0
        features['flow_bytes_per_second'] = (features['num_forward_bytes'] + 
                                             features['num_backward_bytes']) / duration_sec if duration_sec > 0 else 0
        
        # ============ PROTOCOL & DIRECTION ============
        features['protocol_type'] = float(flow.key.proto)  # 6=TCP, 17=UDP, etc.
        features['direction_value'] = float(flow.packets[0].direction if flow.packets else 0)
        
        # ============ PORT ENTROPY ============
        features['source_port_entropy'] = float(flow.key.src_port % 256) / 256.0  # Simplified
        features['dest_port_entropy'] = float(flow.key.dst_port % 256) / 256.0
        
        # ============ SEGMENT SIZE ============
        total_fwd_bytes = features['num_forward_bytes']
        total_bwd_bytes = features['num_backward_bytes']
        
        features['avg_fwd_segment_size'] = (total_fwd_bytes / len(fwd_packets) 
                                           if len(fwd_packets) > 0 else 0)
        features['avg_bwd_segment_size'] = (total_bwd_bytes / len(bwd_packets) 
                                           if len(bwd_packets) > 0 else 0)
        
        # ============ BULK RATE ============
        # Simplified: proportion of large packets
        large_threshold = 1000
        fwd_large = sum(1 for p in fwd_packets if p.captured_len > large_threshold)
        bwd_large = sum(1 for p in bwd_packets if p.captured_len > large_threshold)
        
        features['fwd_bulk_rate'] = (fwd_large / len(fwd_packets) 
                                    if len(fwd_packets) > 0 else 0)
        features['bwd_bulk_rate'] = (bwd_large / len(bwd_packets) 
                                    if len(bwd_packets) > 0 else 0)
        
        return features
    
    @staticmethod
    def _compute_len_stats(packets: List[PacketRecordV1]) -> Dict[str, float]:
        """Compute min/max/mean/std of packet lengths"""
        
        if not packets:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
        
        lengths = [float(p.captured_len) for p in packets]
        
        return {
            'min': float(min(lengths)),
            'max': float(max(lengths)),
            'mean': float(statistics.mean(lengths)),
            'std': float(statistics.stdev(lengths) if len(lengths) > 1 else 0)
        }
    
    @staticmethod
    def _compute_iat_stats(packets: List[PacketRecordV1]) -> Dict[str, float]:
        """Compute min/max/mean/std of inter-arrival times (in seconds)"""
        
        if len(packets) < 2:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
        
        # Get timestamps
        timestamps = [p.mono_ts_ns for p in packets]
        
        # Compute IAT in seconds
        iats = [(timestamps[i+1] - timestamps[i]) / 1e9 
                for i in range(len(timestamps) - 1)]
        
        if not iats:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
        
        return {
            'min': float(min(iats)),
            'max': float(max(iats)),
            'mean': float(statistics.mean(iats)),
            'std': float(statistics.stdev(iats) if len(iats) > 1 else 0)
        }
    
    @staticmethod
    def _count_tcp_flag(packets: List[PacketRecordV1], flag: int) -> int:
        """Count packets with specific TCP flag"""
        
        # Only TCP (proto=6) can have these flags
        return sum(1 for p in packets if p.proto == 6 and (p.tcp_flags & flag))


def build_feature_batch(flows: List[Flow]) -> Tuple[np.ndarray, List[Dict]]:
    """
    Build feature batch from list of flows.
    
    Args:
        flows: List of Flow objects
    
    Returns:
        (X, meta) where:
        - X: numpy array of shape (n, 48)
        - meta: list of dicts with flow metadata
    """
    
    X = []
    meta = []
    
    for flow in flows:
        # Extract features
        features = FeatureBuilder.build_features(flow)
        
        # Convert to array in FEATURE_COLUMNS order
        feature_values = [features.get(col, 0.0) for col in FEATURE_COLUMNS]
        X.append(feature_values)
        
        # Store metadata for later (blocking, etc.)
        meta.append({
            'flow_key': flow.key,
            'src_ip': flow.key.src_ip,
            'src_port': flow.key.src_port,
            'dst_ip': flow.key.dst_ip,
            'dst_port': flow.key.dst_port,
            'proto': flow.key.proto,
            'num_packets': len(flow.packets),
            'num_fwd_packets': len(flow.forward_packets),
            'num_bwd_packets': len(flow.backward_packets),
            'duration': flow.get_duration_seconds(),
            'features': features,
        })
    
    # Convert to numpy array
    X_array = np.array(X, dtype=np.float32)
    
    return X_array, meta


def name(n):
    return n+100*n