"""
File: src/flow_builder/flow.py

Represents a single bidirectional flow with forward/backward direction
"""

import time
from typing import List, Tuple
from ..core.kernel_panel import PacketRecordV1, FlowKeyV1


class Flow:
    """
    Represents one bidirectional flow.
    
    Handles:
    - Canonical endpoint ordering
    - Forward vs. Backward packet separation
    - Timing information
    """
    
    def __init__(self, key: FlowKeyV1, first_packet: PacketRecordV1):
        """
        Initialize flow with first packet.
        
        Args:
            key: Canonical FlowKeyV1
            first_packet: First PacketRecordV1 in flow
        """
        
        self.key = key
        self.packets: List[PacketRecordV1] = [first_packet]
        
        # Timing
        self.start_time = time.time()
        self.last_packet_time = self.start_time
        self.start_ts_ns = first_packet.mono_ts_ns
        self.last_ts_ns = first_packet.mono_ts_ns
        
        # Forward/Backward tracking
        self.forward_packets: List[PacketRecordV1] = []
        self.backward_packets: List[PacketRecordV1] = []
        self._categorize_packet(first_packet)
    
    def add_packet(self, pkt: PacketRecordV1):
        """Add packet to flow"""
        
        self.packets.append(pkt)
        self.last_packet_time = time.time()
        self.last_ts_ns = pkt.mono_ts_ns
        
        self._categorize_packet(pkt)
    
    def _categorize_packet(self, pkt: PacketRecordV1):
        """
        Categorize packet as forward or backward.
        
        Forward: key's source IP → destination IP
        Backward: reverse direction
        """
        
        # Get key's canonical endpoints
        key_src = (self.key.src_ip, self.key.src_port)
        key_dst = (self.key.dst_ip, self.key.dst_port)
        
        # Get packet's endpoints
        pkt_src = (pkt.src_ip, pkt.src_port)
        pkt_dst = (pkt.dst_ip, pkt.dst_port)
        
        # Determine direction
        if pkt_src == key_src and pkt_dst == key_dst:
            # Forward: A→B
            self.forward_packets.append(pkt)
        elif pkt_src == key_dst and pkt_dst == key_src:
            # Backward: B→A
            self.backward_packets.append(pkt)
        else:
            # This shouldn't happen if key is correct
            # Default to forward
            self.forward_packets.append(pkt)
    
    def get_duration_seconds(self) -> float:
        """Get flow duration from first to last packet (wall-clock)"""
        return self.last_packet_time - self.start_time
    
    def get_duration_ns(self) -> int:
        """Get flow duration from first to last packet (nanoseconds)"""
        return self.last_ts_ns - self.start_ts_ns
    
    def __repr__(self):
        return (f"Flow({self.key}, "
                f"packets={len(self.packets)}, "
                f"fwd={len(self.forward_packets)}, "
                f"bwd={len(self.backward_packets)}, "
                f"duration={self.get_duration_seconds():.2f}s)")
    
    def __len__(self):
        return len(self.packets)