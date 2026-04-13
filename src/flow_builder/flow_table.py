"""
File: src/flow_builder/flow_table.py

Manages flow table with timeouts and finalization
Collects packets into bidirectional flows
"""

import time
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from ..core.kernel_panel import PacketRecordV1, FlowKeyV1
from .flow import Flow


class FlowTable:
    """
    Flow table that:
    1. Groups packets by bidirectional flow key
    2. Detects TCP close (FIN/RST)
    3. Manages flow timeouts
    4. Returns finalized flows for feature extraction
    """
    
    def __init__(self, 
                inactive_timeout: float = 10.0,   # seconds
                active_timeout: float = 60.0):     # seconds
        """
        Args:
            inactive_timeout: Flow closes if no packet for N seconds
            active_timeout: Force close flow after N seconds active
        """
        self.flows: Dict[FlowKeyV1, Flow] = {}
        self.inactive_timeout = inactive_timeout
        self.active_timeout = active_timeout
        
        self.finalized_flows: List[Flow] = []
        self.last_timeout_check = time.time()
    
    def add_packet(self, pkt: PacketRecordV1) -> Optional[Flow]:
        """
        Add packet to flow table.
        
        Returns:
            Finalized flow if this packet causes a flow to close, else None
        """
        
        # 1. Create canonical flow key
        flow_key = self._make_flow_key(pkt)
        
        # 2. Get or create flow
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(flow_key, pkt)
            finalized = None
        else:
            self.flows[flow_key].add_packet(pkt)
            finalized = None
        
        # 3. Check TCP close flags (FIN/RST)
        finalized = self._check_tcp_close(pkt, flow_key)
        
        # 4. Check timeouts (periodic)
        now = time.time()
        if now - self.last_timeout_check > 1.0:  # Check every 1 second
            self._check_timeouts()
            self.last_timeout_check = now
        
        return finalized
    
    def get_finalized_flows(self) -> List[Flow]:
        """
        Get list of recently finalized flows and clear buffer.
        Call periodically to process flows.
        """
        result = self.finalized_flows.copy()
        self.finalized_flows.clear()
        return result
    
    def _make_flow_key(self, pkt: PacketRecordV1) -> FlowKeyV1:
        """
        Create canonical bidirectional flow key.
        
        Ensures:
        - A→B and B→A have same key
        - Deterministic ordering
        """
        
        # Build two endpoints
        endpoint_a = (pkt.src_ip, pkt.src_port)
        endpoint_b = (pkt.dst_ip, pkt.dst_port)
        
        # Canonical order: sort alphabetically
        if endpoint_a < endpoint_b:
            src_ip, src_port = endpoint_a
            dst_ip, dst_port = endpoint_b
        else:
            src_ip, src_port = endpoint_b
            dst_ip, dst_port = endpoint_a
        
        return FlowKeyV1(
            ip_version=pkt.ip_version,
            proto=pkt.proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port
        )
    
    def _check_tcp_close(self, pkt: PacketRecordV1, flow_key: FlowKeyV1) -> Optional[Flow]:
        """
        Check if TCP FIN or RST received.
        If so, finalize the flow immediately.
        """
        
        if flow_key not in self.flows:
            return None
        
        # Only TCP can have FIN/RST
        if pkt.proto != 6:  # 6 = TCP
            return None
        
        # TCP flags: 0x01=FIN, 0x04=RST
        if pkt.tcp_flags & 0x01 or pkt.tcp_flags & 0x04:
            # Finalize immediately
            return self._finalize_flow(flow_key)
        
        return None
    
    def _check_timeouts(self):
        """
        Check all flows for timeouts:
        - Inactive: no packet for N seconds
        - Active: flow open for N seconds total
        """
        
        now = time.time()
        keys_to_remove = []
        
        for key, flow in self.flows.items():
            # Check inactive timeout
            if now - flow.last_packet_time > self.inactive_timeout:
                keys_to_remove.append(key)
                continue
            
            # Check active timeout
            if now - flow.start_time > self.active_timeout:
                keys_to_remove.append(key)
                continue
        
        # Finalize timed-out flows
        for key in keys_to_remove:
            self._finalize_flow(key)
    
    def _finalize_flow(self, flow_key: FlowKeyV1) -> Optional[Flow]:
        """Remove flow from table and add to finalized list"""
        
        if flow_key not in self.flows:
            return None
        
        flow = self.flows.pop(flow_key)
        self.finalized_flows.append(flow)
        
        return flow
    
    def get_stats(self) -> Dict:
        """Get flow table statistics"""
        
        return {
            'active_flows': len(self.flows),
            'finalized_flows': len(self.finalized_flows),
            'total_packets': sum(len(f.packets) for f in self.flows.values()) +
                            sum(len(f.packets) for f in self.finalized_flows),
        }