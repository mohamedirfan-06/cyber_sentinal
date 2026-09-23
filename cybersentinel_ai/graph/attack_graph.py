"""Attack graph representation for visualization."""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid

from ..core.indicators import is_external_ip
from ..core.schemas import SecurityEvent, EventSource, EventType
from ..correlation.correlation_engine import AttackChain, CorrelatedEvent


class NodeType(str, Enum):
    """Types of nodes in the attack graph."""
    IP = "ip"
    USER = "user"
    DEVICE = "device"
    PROCESS = "process"
    DESTINATION = "destination"
    FILE = "file"
    SESSION = "session"


class EdgeType(str, Enum):
    """Types of edges in the attack graph."""
    LOGGED_INTO = "logged_into"
    ACCESSED = "accessed"
    EXECUTED = "executed"
    CONNECTED_TO = "connected_to"
    TRANSFERRED_TO = "transferred_to"
    ESCALATED_ON = "escalated_on"
    SPAWNED = "spawned"


@dataclass
class GraphNode:
    """Node in the attack graph."""
    node_id: str
    node_type: NodeType
    label: str
    value: str  # The actual value (IP, username, hostname, etc.)
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_ids: List[str] = field(default_factory=list)  # IDs of events this node appears in
    risk_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "type": self.node_type.value,
            "label": self.label,
            "value": self.value,
            "metadata": self.metadata,
            "event_ids": self.event_ids,
            "risk_score": self.risk_score,
        }


@dataclass
class GraphEdge:
    """Edge in the attack graph."""
    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_ids: List[str] = field(default_factory=list)
    weight: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.edge_id,
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "label": self.label,
            "metadata": self.metadata,
            "event_ids": self.event_ids,
            "weight": self.weight,
        }


@dataclass
class AttackGraph:
    """Complete attack graph representation."""
    graph_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "metadata": self.metadata,
        }
    
    def to_cytoscape(self) -> Dict[str, Any]:
        """Export in Cytoscape.js compatible format."""
        elements = {
            "nodes": [
                {
                    "data": n.to_dict(),
                    "classes": f"node-{n.node_type.value}"
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "data": e.to_dict(),
                    "classes": f"edge-{e.edge_type.value}"
                }
                for e in self.edges
            ]
        }
        return elements


class AttackGraphBuilder:
    """Builds attack graphs from correlated events and attack chains."""
    
    def __init__(self):
        self.node_map: Dict[str, GraphNode] = {}  # (type, value) -> node
        self.edge_list: List[GraphEdge] = []
    
    def build_from_chain(self, chain: AttackChain) -> AttackGraph:
        """Build attack graph from a single attack chain."""
        self.node_map = {}
        self.edge_list = []
        
        # Process each event in the chain
        for correlated_event in chain.events:
            self._process_event(correlated_event)
        
        # Add chain metadata
        metadata = {
            "chain_id": chain.chain_id,
            "attack_type": chain.attack_type,
            "start_time": chain.start_time.isoformat() if chain.start_time else None,
            "end_time": chain.end_time.isoformat() if chain.end_time else None,
            "correlation_score": chain.correlation_score,
            "event_count": len(chain.events),
            "entities": {k: list(v) for k, v in chain.entities.items()},
        }
        
        graph = AttackGraph(
            graph_id=chain.chain_id,
            nodes=list(self.node_map.values()),
            edges=self.edge_list,
            metadata=metadata,
        )
        
        return graph
    
    def build_from_chains(self, chains: List[AttackChain]) -> AttackGraph:
        """Build combined attack graph from multiple chains."""
        self.node_map = {}
        self.edge_list = []
        
        all_events = []
        for chain in chains:
            all_events.extend(chain.events)
        all_events = list({ce.event.event_id: ce for ce in all_events}.values())
        
        # Sort by timestamp
        all_events.sort(key=lambda ce: ce.event.timestamp)
        
        for correlated_event in all_events:
            self._process_event(correlated_event)
        
        # Combine metadata
        metadata = {
            "chain_count": len(chains),
            "total_events": len(all_events),
            "attack_types": list(set(c.attack_type for c in chains)),
            "start_time": min(c.start_time for c in chains).isoformat() if chains else None,
            "end_time": max(c.end_time for c in chains).isoformat() if chains else None,
            "combined_correlation_score": max(c.correlation_score for c in chains) if chains else 0,
        }
        
        graph = AttackGraph(
            graph_id=str(uuid.uuid4())[:8],
            nodes=list(self.node_map.values()),
            edges=self.edge_list,
            metadata=metadata,
        )
        
        return graph
    
    def build_from_events(self, events: List[SecurityEvent]) -> AttackGraph:
        """Build attack graph directly from events."""
        self.node_map = {}
        self.edge_list = []
        
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        for event in sorted_events:
            self._process_event_simple(event)
        
        graph = AttackGraph(
            graph_id=str(uuid.uuid4())[:8],
            nodes=list(self.node_map.values()),
            edges=self.edge_list,
            metadata={
                "event_count": len(events),
                "source_types": list(set(e.source.value for e in events)),
            },
        )
        
        return graph
    
    def _process_event(self, correlated_event: CorrelatedEvent):
        """Process a correlated event and add nodes/edges."""
        event = correlated_event.event
        self._process_event_simple(event)
    
    def _process_event_simple(self, event: SecurityEvent):
        """Process a simple event and add nodes/edges."""
        event_id = event.event_id
        
        # Create or get nodes
        ip_node = None
        if event.source_ip:
            ip_node = self._get_or_create_node(
                NodeType.IP, event.source_ip, f"IP: {event.source_ip}",
                {"is_external": self._is_external_ip(event.source_ip)},
                event_id
            )
        
        user_node = None
        if event.user:
            user_node = self._get_or_create_node(
                NodeType.USER, event.user, f"User: {event.user}",
                {},
                event_id
            )
        
        device_node = None
        if event.device:
            device_node = self._get_or_create_node(
                NodeType.DEVICE, event.device, f"Device: {event.device}",
                {},
                event_id
            )
        
        dest_node = None
        if event.destination_ip:
            dest_node = self._get_or_create_node(
                NodeType.DESTINATION, event.destination_ip, f"Dest: {event.destination_ip}",
                {"is_external": self._is_external_ip(event.destination_ip)},
                event_id
            )
        
        process_node = None
        if event.metadata.get("process_name"):
            process_node = self._get_or_create_node(
                NodeType.PROCESS, event.metadata["process_name"], f"Process: {event.metadata['process_name']}",
                {"pid": event.metadata.get("pid")},
                event_id
            )
        
        file_node = None
        if event.metadata.get("file_path"):
            file_node = self._get_or_create_node(
                NodeType.FILE, event.metadata["file_path"], f"File: {event.metadata['file_path']}",
                {"size": event.metadata.get("size")},
                event_id
            )
        
        session_node = None
        if event.metadata.get("session_id"):
            session_node = self._get_or_create_node(
                NodeType.SESSION, event.metadata["session_id"], f"Session: {event.metadata['session_id']}",
                {},
                event_id
            )
        
        # Create edges based on event type
        self._create_edges_for_event(event, event_id, ip_node, user_node, device_node, 
                                    dest_node, process_node, file_node, session_node)
    
    def _get_or_create_node(
        self, 
        node_type: NodeType, 
        value: str, 
        label: str, 
        metadata: Dict[str, Any],
        event_id: str
    ) -> GraphNode:
        """Get existing node or create new one."""
        key = (node_type.value, value)
        
        if key in self.node_map:
            node = self.node_map[key]
            if event_id not in node.event_ids:
                node.event_ids.append(event_id)
            return node
        
        node = GraphNode(
            node_id=str(uuid.uuid4())[:8],
            node_type=node_type,
            label=label,
            value=value,
            metadata=metadata,
            event_ids=[event_id],
        )
        self.node_map[key] = node
        return node
    
    def _create_edges_for_event(
        self,
        event: SecurityEvent,
        event_id: str,
        ip_node: Optional[GraphNode],
        user_node: Optional[GraphNode],
        device_node: Optional[GraphNode],
        dest_node: Optional[GraphNode],
        process_node: Optional[GraphNode],
        file_node: Optional[GraphNode],
        session_node: Optional[GraphNode],
    ):
        """Create edges based on event type."""
        edges_to_create = []
        
        if event.event_type == EventType.SUCCESSFUL_LOGIN or event.event_type == EventType.FAILED_LOGIN:
            if ip_node and user_node:
                edges_to_create.append((
                    ip_node, user_node, EdgeType.LOGGED_INTO, 
                    f"{'Failed' if event.event_type == EventType.FAILED_LOGIN else 'Successful'} login"
                ))
            if user_node and device_node:
                edges_to_create.append((
                    user_node, device_node, EdgeType.LOGGED_INTO,
                    f"Login to {device_node.value}"
                ))
        
        elif event.event_type == EventType.PROCESS_EXECUTION or event.event_type == EventType.POWERSHELL_EXECUTION or event.event_type == EventType.SUSPICIOUS_PROCESS:
            if user_node and process_node:
                edges_to_create.append((
                    user_node, process_node, EdgeType.EXECUTED,
                    f"Executed {process_node.value}"
                ))
            if process_node and device_node:
                edges_to_create.append((
                    process_node, device_node, EdgeType.EXECUTED,
                    f"Running on {device_node.value}"
                ))
        
        elif event.event_type == EventType.FILE_ACCESS:
            if user_node and file_node:
                action = event.action.value if event.action else "accessed"
                edges_to_create.append((
                    user_node, file_node, EdgeType.ACCESSED,
                    f"{action} file"
                ))
            if process_node and file_node:
                edges_to_create.append((
                    process_node, file_node, EdgeType.ACCESSED,
                    f"Process accessed file"
                ))
        
        elif event.event_type in [EventType.CONNECTION, EventType.DATA_TRANSFER]:
            if ip_node and dest_node:
                edge_type = EdgeType.TRANSFERRED_TO if event.event_type == EventType.DATA_TRANSFER else EdgeType.CONNECTED_TO
                bytes_sent = event.metadata.get("bytes_sent", 0)
                label = f"Transferred {bytes_sent:,} bytes" if event.event_type == EventType.DATA_TRANSFER else "Connected"
                edges_to_create.append((
                    ip_node, dest_node, edge_type, label
                ))
            if user_node and dest_node:
                edges_to_create.append((
                    user_node, dest_node, EdgeType.CONNECTED_TO,
                    f"User connection to {dest_node.value}"
                ))
        
        elif event.event_type == EventType.PRIVILEGE_ESCALATION:
            if user_node and device_node:
                edges_to_create.append((
                    user_node, device_node, EdgeType.ESCALATED_ON,
                    f"Privilege escalation: {event.metadata.get('privilege_change', 'unknown')}"
                ))
        
        # Add all edges
        for source, target, edge_type, label in edges_to_create:
            edge = GraphEdge(
                edge_id=str(uuid.uuid4())[:8],
                source_id=source.node_id,
                target_id=target.node_id,
                edge_type=edge_type,
                label=label,
                metadata={
                    "event_type": event.event_type.value,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                },
                event_ids=[event_id],
            )
            self.edge_list.append(edge)
    
    _is_external_ip = staticmethod(is_external_ip)


def build_attack_graph(chain: AttackChain) -> AttackGraph:
    """Convenience function to build graph from chain."""
    builder = AttackGraphBuilder()
    return builder.build_from_chain(chain)


def build_attack_graphs(chains: List[AttackChain]) -> AttackGraph:
    """Convenience function to build graph from multiple chains."""
    builder = AttackGraphBuilder()
    return builder.build_from_chains(chains)
