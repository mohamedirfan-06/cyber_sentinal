"""Event correlation engine for building attack chains."""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, replace
from collections import defaultdict
from enum import Enum
import uuid

from ..core.schemas import SecurityEvent, EventSource, EventType, Action
from ..core.config import Config, DEFAULT_CONFIG, CorrelationConfig
from ..rules.rule_engine import RuleMatch, RuleType


class CorrelationType(str, Enum):
    """Types of correlation."""
    TEMPORAL = "temporal"
    ENTITY_BASED = "entity_based"
    ATTACK_CHAIN = "attack_chain"


@dataclass
class CorrelatedEvent:
    """An event within a correlation chain."""
    event: SecurityEvent
    sequence_number: int
    correlation_reasons: List[str]
    linked_entities: Dict[str, str]  # entity_type -> entity_value


@dataclass
class AttackChain:
    """Represents a correlated attack chain."""
    chain_id: str
    events: List[CorrelatedEvent]
    start_time: datetime
    end_time: datetime
    entities: Dict[str, Set[str]]  # entity_type -> set of values
    rule_matches: List[RuleMatch]
    correlation_score: float  # 0.0 to 1.0
    attack_type: str
    description: str


class CorrelationEngine:
    """Correlates security events into attack chains."""
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.corr_config: CorrelationConfig = self.config.correlation
    
    def correlate(self, events: List[SecurityEvent], rule_matches: List[RuleMatch]) -> List[AttackChain]:
        """Correlate events into attack chains using multiple strategies."""
        if not events:
            return []
        # Shared entities and timing alone are not evidence of an attack.
        if not rule_matches:
            return []
        evidence_ids = {e.event_id for rm in rule_matches for e in rm.matched_events}
        events = [e for e in events if e.event_id in evidence_ids]
        
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Strategy 1: Entity-based correlation (IP, user, device)
        entity_chains = self._correlate_by_entities(sorted_events, rule_matches)
        
        # Strategy 2: Temporal correlation (events close in time)
        temporal_chains = self._correlate_temporal(sorted_events, rule_matches)
        
        # Strategy 3: Attack chain correlation (sequential attack patterns)
        attack_chains = self._correlate_attack_patterns(sorted_events, rule_matches)
        
        # Merge and deduplicate chains
        all_chains = entity_chains + temporal_chains + attack_chains
        merged_chains = self._merge_chains(all_chains)
        
        # Filter by minimum score and length
        filtered_chains = [
            c for c in merged_chains
            if c.correlation_score >= self.corr_config.min_chain_score
            and len(c.events) >= 2
        ]
        
        # Sort by score descending
        filtered_chains.sort(key=lambda c: (c.correlation_score, len(c.events)), reverse=True)
        
        bounded = []
        limit = self.corr_config.max_chain_length
        for chain in filtered_chains:
            if len(chain.events) <= limit:
                bounded.append(chain)
                continue
            # Overlap one event between segments to preserve the connection,
            # including the final evidence that truncation used to discard.
            for start in range(0, len(chain.events) - 1, limit - 1):
                segment = [replace(ce, sequence_number=i)
                           for i, ce in enumerate(chain.events[start:start + limit])]
                raw = [ce.event for ce in segment]
                ids = {e.event_id for e in raw}
                matches = [rm for rm in chain.rule_matches
                           if any(e.event_id in ids for e in rm.matched_events)]
                score = self._calculate_chain_score(segment, matches)
                if score < self.corr_config.min_chain_score:
                    continue
                bounded.append(replace(
                    chain, chain_id=str(uuid.uuid4())[:8], events=segment,
                    start_time=raw[0].timestamp, end_time=raw[-1].timestamp,
                    entities=self._extract_entities_from_events(raw), rule_matches=matches,
                    correlation_score=score,
                    attack_type=self._infer_attack_type(list(enumerate(raw)), matches),
                    description=f"Correlated segment containing {len(raw)} events",
                ))
        bounded = self._merge_chains(bounded)
        bounded.sort(key=lambda c: (c.correlation_score, len(c.events)), reverse=True)
        return bounded
    
    def _correlate_by_entities(
        self, 
        events: List[SecurityEvent], 
        rule_matches: List[RuleMatch]
    ) -> List[AttackChain]:
        """Correlate events sharing common entities (IP, user, device)."""
        chains = []
        
        # Build entity -> events mapping
        entity_events = defaultdict(list)
        for i, event in enumerate(events):
            if event.source_ip and "source_ip" in self.corr_config.correlation_keys:
                entity_events[("source_ip", event.source_ip)].append((i, event))
            if event.destination_ip and "destination_ip" in self.corr_config.correlation_keys:
                entity_events[("destination_ip", event.destination_ip)].append((i, event))
            if event.user and "user" in self.corr_config.correlation_keys:
                entity_events[("user", event.user)].append((i, event))
            if event.device and "device" in self.corr_config.correlation_keys:
                entity_events[("device", event.device)].append((i, event))
            if event.metadata.get("process_name") and "process" in self.corr_config.correlation_keys:
                entity_events[("process", event.metadata["process_name"])].append((i, event))
            if event.metadata.get("session_id") and "session_id" in self.corr_config.correlation_keys:
                entity_events[("session", event.metadata["session_id"])].append((i, event))
        
        # Find entities with multiple events
        for (entity_type, entity_value), event_list in entity_events.items():
            if len(event_list) < 2:
                continue
            
            # Sort by timestamp
            event_list.sort(key=lambda x: x[1].timestamp)
            
            # Group into time windows
            window_chains = self._group_by_time_window(event_list)
            
            for chain_events in window_chains:
                if len(chain_events) < 2:
                    continue
                
                correlated_events = [
                    CorrelatedEvent(
                        event=evt,
                        sequence_number=idx,
                        correlation_reasons=[f"shared_{entity_type}:{entity_value}"],
                        linked_entities={entity_type: entity_value},
                    )
                    for idx, (_, evt) in enumerate(chain_events)
                ]
                
                # Find relevant rule matches
                chain_rule_matches = [
                    rm for rm in rule_matches
                    if any(self._event_in_chain(rm, evt) for _, evt in chain_events)
                ]
                
                chain = AttackChain(
                    chain_id=str(uuid.uuid4())[:8],
                    events=correlated_events,
                    start_time=chain_events[0][1].timestamp,
                    end_time=chain_events[-1][1].timestamp,
                    entities=self._extract_entities(chain_events),
                    rule_matches=chain_rule_matches,
                    correlation_score=self._calculate_chain_score(correlated_events, chain_rule_matches),
                    attack_type=self._infer_attack_type(chain_events, chain_rule_matches),
                    description=f"Entity-correlated chain via {entity_type}={entity_value} ({len(chain_events)} events)",
                )
                chains.append(chain)
        
        return chains
    
    def _correlate_temporal(
        self, 
        events: List[SecurityEvent], 
        rule_matches: List[RuleMatch]
    ) -> List[AttackChain]:
        """Correlate events that occur close in time."""
        chains = []
        window_minutes = self.corr_config.time_window_minutes
        
        for i, anchor in enumerate(events):
            window_end = anchor.timestamp + timedelta(minutes=window_minutes)
            window_events = [
                (j, e) for j, e in enumerate(events)
                if anchor.timestamp <= e.timestamp <= window_end
            ]
            
            if len(window_events) < 3:  # Need at least 3 events for temporal chain
                continue
            
            # Check if events are from different sources (cross-source correlation)
            sources = set(e.source for _, e in window_events)
            if len(sources) < 2:
                continue
            
            correlated_events = [
                CorrelatedEvent(
                    event=evt,
                    sequence_number=idx,
                    correlation_reasons=["temporal_proximity"],
                    linked_entities={},
                )
                for idx, (_, evt) in enumerate(window_events)
            ]
            
            chain_rule_matches = [
                rm for rm in rule_matches
                if any(self._event_in_chain(rm, evt) for _, evt in window_events)
            ]
            if not self._share_entity([evt for _, evt in window_events]):
                continue
            
            chain = AttackChain(
                chain_id=str(uuid.uuid4())[:8],
                events=correlated_events,
                start_time=window_events[0][1].timestamp,
                end_time=window_events[-1][1].timestamp,
                entities=self._extract_entities(window_events),
                rule_matches=chain_rule_matches,
                correlation_score=self._calculate_chain_score(correlated_events, chain_rule_matches) * 0.8,  # Lower base score
                attack_type=self._infer_attack_type(window_events, chain_rule_matches),
                description=f"Temporal correlation: {len(window_events)} events across {len(sources)} sources in {window_minutes}min",
            )
            chains.append(chain)
        
        return chains
    
    def _correlate_attack_patterns(
        self, 
        events: List[SecurityEvent], 
        rule_matches: List[RuleMatch]
    ) -> List[AttackChain]:
        """Correlate events following known attack patterns."""
        chains = []
        
        # Define attack pattern sequences
        patterns = {
            "brute_force_to_compromise": [
                (EventSource.AUTHENTICATION, EventType.FAILED_LOGIN),
                (EventSource.AUTHENTICATION, EventType.SUCCESSFUL_LOGIN),
                (EventSource.AUTHENTICATION, EventType.PRIVILEGE_ESCALATION),
                (EventSource.ENDPOINT, EventType.POWERSHELL_EXECUTION),
                (EventSource.ENDPOINT, EventType.FILE_ACCESS),
                (EventSource.NETWORK, EventType.DATA_TRANSFER),
            ],
            "credential_theft_lateral": [
                (EventSource.AUTHENTICATION, EventType.SUCCESSFUL_LOGIN),
                (EventSource.AUTHENTICATION, EventType.SUCCESSFUL_LOGIN),  # New IP
                (EventSource.ENDPOINT, EventType.PROCESS_EXECUTION),
                (EventSource.NETWORK, EventType.CONNECTION),
            ],
            "malware_execution_exfil": [
                (EventSource.ENDPOINT, EventType.SUSPICIOUS_PROCESS),
                (EventSource.ENDPOINT, EventType.POWERSHELL_EXECUTION),
                (EventSource.ENDPOINT, EventType.FILE_ACCESS),
                (EventSource.NETWORK, EventType.DATA_TRANSFER),
            ],
        }
        
        for pattern_name, pattern in patterns.items():
            matched_chains = self._match_pattern(events, pattern, rule_matches)
            for chain_events in matched_chains:
                correlated_events = [
                    CorrelatedEvent(
                        event=evt,
                        sequence_number=idx,
                        correlation_reasons=[f"pattern:{pattern_name}", f"step_{idx}:{evt.event_type.value}"],
                        linked_entities=self._get_linked_entities(evt),
                    )
                    for idx, evt in enumerate(chain_events)
                ]
                
                chain_rule_matches = [
                    rm for rm in rule_matches
                    if any(self._event_in_chain(rm, evt) for evt in chain_events)
                ]
                
                chain = AttackChain(
                    chain_id=str(uuid.uuid4())[:8],
                    events=correlated_events,
                    start_time=chain_events[0].timestamp,
                    end_time=chain_events[-1].timestamp,
                    entities=self._extract_entities_from_events(chain_events),
                    rule_matches=chain_rule_matches,
                    correlation_score=min(1.0, self._calculate_chain_score(correlated_events, chain_rule_matches) * 1.2),
                    attack_type=pattern_name,
                    description=f"Attack pattern '{pattern_name}' matched: {len(chain_events)} steps",
                )
                chains.append(chain)
        
        return chains
    
    def _match_pattern(
        self, 
        events: List[SecurityEvent], 
        pattern: List[Tuple[EventSource, EventType]],
        rule_matches: List[RuleMatch]
    ) -> List[List[SecurityEvent]]:
        """Find event sequences matching a pattern."""
        matches = []
        pattern_len = len(pattern)
        
        for i in range(len(events) - pattern_len + 1):
            window = events[i:i + pattern_len * 3]  # Allow gaps
            
            matched = []
            pattern_idx = 0
            
            for event in window:
                if pattern_idx < pattern_len:
                    expected_source, expected_type = pattern[pattern_idx]
                    if event.source == expected_source and event.event_type == expected_type:
                        matched.append(event)
                        pattern_idx += 1
            
            if pattern_idx == pattern_len:
                # Check time window constraint
                time_span = (matched[-1].timestamp - matched[0].timestamp).total_seconds() / 60
                if time_span <= self.corr_config.time_window_minutes * 2 and self._share_entity(matched):
                    matches.append(matched)
        
        return matches

    def _share_entity(self, events):
        """Require a common configured entity for temporal/pattern chains."""
        for key in self.corr_config.correlation_keys:
            values = [e.metadata.get("process_name" if key == "process" else key)
                      if key in ("process", "session_id") else getattr(e, key, None)
                      for e in events]
            if values and all(v and v == values[0] for v in values):
                return True
        return False
    
    def _group_by_time_window(self, event_list: List[Tuple[int, SecurityEvent]]) -> List[List[Tuple[int, SecurityEvent]]]:
        """Group events by time window."""
        if not event_list:
            return []
        
        groups = []
        current_group = [event_list[0]]
        window_minutes = self.corr_config.time_window_minutes
        
        for i in range(1, len(event_list)):
            prev_time = current_group[0][1].timestamp
            curr_time = event_list[i][1].timestamp
            
            if (curr_time - prev_time).total_seconds() / 60 <= window_minutes:
                current_group.append(event_list[i])
            else:
                if len(current_group) >= 2:
                    groups.append(current_group)
                current_group = [event_list[i]]
        
        if len(current_group) >= 2:
            groups.append(current_group)
        
        return groups
    
    def _extract_entities(self, event_list: List[Tuple[int, SecurityEvent]]) -> Dict[str, Set[str]]:
        """Extract unique entities from event list."""
        entities = defaultdict(set)
        for _, event in event_list:
            if event.source_ip:
                entities["source_ips"].add(event.source_ip)
            if event.destination_ip:
                entities["destination_ips"].add(event.destination_ip)
            if event.user:
                entities["users"].add(event.user)
            if event.device:
                entities["devices"].add(event.device)
            if event.metadata.get("process_name"):
                entities["processes"].add(event.metadata["process_name"])
        return dict(entities)
    
    def _extract_entities_from_events(self, events: List[SecurityEvent]) -> Dict[str, Set[str]]:
        """Extract unique entities from event list."""
        entities = defaultdict(set)
        for event in events:
            if event.source_ip:
                entities["source_ips"].add(event.source_ip)
            if event.destination_ip:
                entities["destination_ips"].add(event.destination_ip)
            if event.user:
                entities["users"].add(event.user)
            if event.device:
                entities["devices"].add(event.device)
            if event.metadata.get("process_name"):
                entities["processes"].add(event.metadata["process_name"])
        return dict(entities)
    
    def _get_linked_entities(self, event: SecurityEvent) -> Dict[str, str]:
        """Get linked entities for a single event."""
        entities = {}
        if event.source_ip:
            entities["source_ip"] = event.source_ip
        if event.destination_ip:
            entities["destination_ip"] = event.destination_ip
        if event.user:
            entities["user"] = event.user
        if event.device:
            entities["device"] = event.device
        if event.metadata.get("process_name"):
            entities["process"] = event.metadata["process_name"]
        if event.metadata.get("session_id"):
            entities["session"] = event.metadata["session_id"]
        return entities
    
    def _event_in_chain(self, rule_match: RuleMatch, event: SecurityEvent) -> bool:
        """Check if event is in rule match."""
        return any(e.event_id == event.event_id for e in rule_match.matched_events)
    
    def _calculate_chain_score(self, events: List[CorrelatedEvent], rule_matches: List[RuleMatch]) -> float:
        """Calculate correlation score for a chain."""
        if not events:
            return 0.0
        
        base_score = 0.3
        
        # Length bonus
        length_bonus = min(0.3, len(events) * 0.05)
        
        # Cross-source diversity
        sources = set(e.event.source for e in events)
        diversity_bonus = min(0.2, len(sources) * 0.05)
        
        # Rule match confidence
        rule_bonus = 0.0
        if rule_matches:
            avg_confidence = sum(rm.confidence for rm in rule_matches) / len(rule_matches)
            rule_bonus = avg_confidence * 0.3
        
        # Severity bonus
        severity_bonus = 0.0
        if rule_matches:
            severity_map = {"LOW": 0.05, "MEDIUM": 0.1, "HIGH": 0.15, "CRITICAL": 0.2}
            max_severity = max((rm.severity.value for rm in rule_matches), key=lambda s: severity_map[s])
            severity_bonus = severity_map.get(max_severity, 0)
        
        total = base_score + length_bonus + diversity_bonus + rule_bonus + severity_bonus
        return min(1.0, total)
    
    def _infer_attack_type(self, event_list: List[Tuple[int, SecurityEvent]], rule_matches: List[RuleMatch]) -> str:
        """Infer attack type from events and rule matches."""
        if rule_matches:
            # Use highest severity rule match type
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            top_match = max(rule_matches, key=lambda rm: severity_order.get(rm.severity.value, 0))
            return top_match.rule_type.value
        
        # Infer from event types
        event_types = [e.event_type for _, e in event_list]
        
        if EventType.FAILED_LOGIN in event_types and EventType.SUCCESSFUL_LOGIN in event_types:
            return "brute_force"
        if EventType.POWERSHELL_EXECUTION in event_types and EventType.FILE_ACCESS in event_types:
            return "malware_execution"
        if EventType.DATA_TRANSFER in event_types:
            return "data_exfiltration"
        if EventType.PRIVILEGE_ESCALATION in event_types:
            return "privilege_escalation"
        
        return "suspicious_activity"
    
    def _merge_chains(self, chains: List[AttackChain]) -> List[AttackChain]:
        """Merge overlapping chains."""
        if not chains:
            return []
        
        # Sort by score descending
        chains.sort(key=lambda c: (c.correlation_score, len(c.events)), reverse=True)
        
        merged = []
        for chain in chains:
            # Check if this chain overlaps significantly with any merged chain
            is_duplicate = False
            for existing in merged:
                if self._chains_overlap(chain, existing):
                    is_duplicate = True
                    # Keep the higher scoring one
                    if chain.correlation_score > existing.correlation_score:
                        merged.remove(existing)
                        merged.append(chain)
                    break
            
            if not is_duplicate:
                merged.append(chain)
        
        return merged
    
    def _chains_overlap(self, chain1: AttackChain, chain2: AttackChain) -> bool:
        """Check if two chains overlap significantly."""
        events1 = {e.event.event_id for e in chain1.events}
        events2 = {e.event.event_id for e in chain2.events}
        
        if not events1 or not events2:
            return False
        
        overlap = len(events1 & events2)
        union = len(events1 | events2)
        
        return (overlap / union) > 0.5  # 50% overlap threshold
