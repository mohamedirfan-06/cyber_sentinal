"""MITRE ATT&CK technique mapping layer."""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, replace
from enum import Enum

from ..core.schemas import SecurityEvent, EventSource, EventType, Action
from ..rules.rule_engine import RuleMatch, RuleType
from ..correlation.correlation_engine import AttackChain


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique mapping."""
    technique_id: str
    name: str
    tactic: str
    description: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    event_ids: List[str]


class Tactic(str, Enum):
    """MITRE ATT&CK tactics."""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


# MITRE ATT&CK technique mappings based on observed behaviors
TECHNIQUE_MAPPINGS = {
    # Initial Access
    "T1110": {
        "name": "Brute Force",
        "tactic": Tactic.CREDENTIAL_ACCESS,
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "triggers": ["brute_force", "failed_login_count"],
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": Tactic.CREDENTIAL_ACCESS,
        "description": "Systematic guessing of passwords.",
        "triggers": ["failed_login", "multiple_failed_logins"],
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": Tactic.CREDENTIAL_ACCESS,
        "description": "Trying common passwords across many accounts.",
        "triggers": ["multiple_users_same_ip"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": Tactic.INITIAL_ACCESS,
        "description": "Use of valid credentials for initial access.",
        "triggers": ["new_ip", "unusual_time"],
    },
    "T1078.002": {
        "name": "Domain Accounts",
        "tactic": Tactic.INITIAL_ACCESS,
        "description": "Use of valid domain credentials.",
        "triggers": ["domain_user"],
    },
    
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": Tactic.EXECUTION,
        "description": "Abuse of command/script interpreters.",
        "triggers": ["powershell", "cmd", "script_execution"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": Tactic.EXECUTION,
        "description": "PowerShell commands/scripts for execution.",
        "triggers": ["powershell_execution", "suspicious_powershell"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": Tactic.EXECUTION,
        "description": "cmd.exe for command execution.",
        "triggers": ["cmd_execution", "cmd.exe"],
    },
    "T1059.007": {
        "name": "JavaScript/JScript",
        "tactic": Tactic.EXECUTION,
        "description": "JavaScript/JScript execution.",
        "triggers": ["wscript", "cscript", "js_execution"],
    },
    
    # Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": Tactic.PRIVILEGE_ESCALATION,
        "description": "Exploiting vulnerabilities for higher privileges.",
        "triggers": ["privilege_escalation", "exploit"],
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": Tactic.PRIVILEGE_ESCALATION,
        "description": "Manipulating access tokens for privilege escalation.",
        "triggers": ["token_manipulation", "privilege_escalation", "impersonation"],
    },
    "T1134.001": {
        "name": "Token Impersonation/Theft",
        "tactic": Tactic.PRIVILEGE_ESCALATION,
        "description": "Impersonating or stealing tokens.",
        "triggers": ["token_impersonation", "token_theft"],
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Discovery of permission groups.",
        "triggers": ["group_enumeration", "privilege_check"],
    },
    
    # Defense Evasion
    "T1562": {
        "name": "Impair Defenses",
        "tactic": Tactic.DEFENSE_EVASION,
        "description": "Disabling or modifying security tools.",
        "triggers": ["disable_av", "disable_defender", "exclusion_path"],
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": Tactic.DEFENSE_EVASION,
        "description": "Disabling security monitoring tools.",
        "triggers": ["set-mppreference", "disable_realtime"],
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": Tactic.DEFENSE_EVASION,
        "description": "Removing evidence of intrusion.",
        "triggers": ["clear_logs", "delete_files", "wevtutil"],
    },
    "T1027": {
        "name": "Obfuscated/Stored Files",
        "tactic": Tactic.DEFENSE_EVASION,
        "description": "Obfuscating malicious code.",
        "triggers": ["encoded_command", "-enc", "obfuscated"],
    },
    
    # Credential Access
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": Tactic.CREDENTIAL_ACCESS,
        "description": "Dumping credentials from OS.",
        "triggers": ["mimikatz", "lsass_dump", "sekurlsa"],
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": Tactic.CREDENTIAL_ACCESS,
        "description": "Dumping LSASS process memory.",
        "triggers": ["lsass", "procdump", "comsvcs.dll"],
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": Tactic.CREDENTIAL_ACCESS,
        "description": "Extracting credentials from password stores.",
        "triggers": ["credential_manager", "vault", "password_store"],
    },
    
    # Discovery
    "T1087": {
        "name": "Account Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Enumerating accounts.",
        "triggers": ["net_user", "get-localuser", "whoami"],
    },
    "T1087.001": {
        "name": "Local Account Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Enumerating local accounts.",
        "triggers": ["get-localuser", "net user"],
    },
    "T1087.002": {
        "name": "Domain Account Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Enumerating domain accounts.",
        "triggers": ["get-aduser", "net user /domain"],
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Discovering remote systems.",
        "triggers": ["nmap", "port_scan", "arp_scan", "net view"],
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Discovering network configuration.",
        "triggers": ["ipconfig", "ifconfig", "route print"],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": Tactic.DISCOVERY,
        "description": "Gathering system information.",
        "triggers": ["systeminfo", "get-computerinfo", "msinfo32"],
    },
    
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": Tactic.LATERAL_MOVEMENT,
        "description": "Using remote services for lateral movement.",
        "triggers": ["rdp", "ssh", "psexec", "wmi", "smb"],
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": Tactic.LATERAL_MOVEMENT,
        "description": "Using RDP for lateral movement.",
        "triggers": ["rdp", "mstsc", "3389"],
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactic": Tactic.LATERAL_MOVEMENT,
        "description": "Using NTLM hashes for authentication.",
        "triggers": ["pass_the_hash", "pth", "sekurlsa::pth"],
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": Tactic.LATERAL_MOVEMENT,
        "description": "Using alternate auth material.",
        "triggers": ["pass_the_ticket", "overpass_the_hash"],
    },
    
    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic": Tactic.COLLECTION,
        "description": "Collecting data from local system.",
        "triggers": ["sensitive_file", "staging", "password_file", "secret_file", "key_file", "shadow"],
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactic": Tactic.COLLECTION,
        "description": "Collecting from network shares.",
        "triggers": ["smb_share", "network_drive", "file_share"],
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": Tactic.COLLECTION,
        "description": "Archiving data for exfiltration.",
        "triggers": ["compress", "zip", "archive", "7zip"],
    },
    
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": Tactic.COMMAND_AND_CONTROL,
        "description": "Using application layer protocols for C2.",
        "triggers": ["http_c2", "https_c2", "dns_c2", "beacon"],
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": Tactic.COMMAND_AND_CONTROL,
        "description": "HTTP/HTTPS for C2.",
        "triggers": ["http_connection", "https_connection", "web_request"],
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": Tactic.COMMAND_AND_CONTROL,
        "description": "Using encrypted channels.",
        "triggers": ["ssl", "tls", "encrypted_c2"],
    },
    
    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over Command and Control Channel",
        "tactic": Tactic.EXFILTRATION,
        "description": "Exfiltrating data over C2 channel.",
        "triggers": ["c2_exfil"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": Tactic.EXFILTRATION,
        "description": "Exfiltration using non-standard protocols.",
        "triggers": ["ftp_exfil", "dns_exfil", "smb_exfil"],
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": Tactic.EXFILTRATION,
        "description": "Exfiltration to web services.",
        "triggers": ["cloud_upload", "web_upload", "api_exfil"],
    },
    
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": Tactic.IMPACT,
        "description": "Encrypting data for ransomware.",
        "triggers": ["ransomware", "encrypt", "file_encryption"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": Tactic.IMPACT,
        "description": "Preventing system recovery.",
        "triggers": ["delete_shadows", "vssadmin", "wbadmin"],
    },
}


class MitreMapper:
    """Maps observed behaviors to MITRE ATT&CK techniques."""
    
    def __init__(self):
        self.techniques = TECHNIQUE_MAPPINGS
    
    def map_events(self, events: List[SecurityEvent]) -> List[MitreTechnique]:
        """Map raw events to MITRE techniques."""
        mapped = []
        
        # Check each technique against events
        for tech_id, tech_info in self.techniques.items():
            evidence = self._check_technique_triggers(events, tech_info["triggers"])
            if evidence:
                mapped.append(MitreTechnique(
                    technique_id=tech_id,
                    name=tech_info["name"],
                    tactic=tech_info["tactic"].value,
                    description=tech_info["description"],
                    confidence=self._calculate_confidence(evidence, tech_info["triggers"]),
                    evidence=evidence,
                    event_ids=[e.event_id for e in events if self._check_technique_triggers([e], tech_info["triggers"])],
                ))
        
        # Sort by confidence descending
        mapped.sort(key=lambda t: t.confidence, reverse=True)
        return mapped
    
    def map_rule_matches(self, rule_matches: List[RuleMatch]) -> List[MitreTechnique]:
        """Map rule matches to MITRE techniques."""
        mapped = []
        
        rule_to_techniques = {
            RuleType.BRUTE_FORCE: ["T1110", "T1110.001"],
            RuleType.ACCOUNT_COMPROMISE: ["T1078"],
            RuleType.SUSPICIOUS_POWERSHELL: ["T1059.001", "T1059"],
            RuleType.DATA_EXFILTRATION: ["T1005"],
            RuleType.COORDINATED_ATTACK: [],
        }
        
        for match in rule_matches:
            tech_ids = rule_to_techniques.get(match.rule_type, [])
            for tech_id in tech_ids:
                if tech_id in self.techniques:
                    tech_info = self.techniques[tech_id]
                    mapped.append(MitreTechnique(
                        technique_id=tech_id,
                        name=tech_info["name"],
                        tactic=tech_info["tactic"].value,
                        description=tech_info["description"],
                        confidence=match.confidence,
                        evidence=[match.description],
                        event_ids=[e.event_id for e in match.matched_events],
                    ))
        
        return self._merge_mappings(mapped)
    
    def map_attack_chains(self, attack_chains: List[AttackChain]) -> List[MitreTechnique]:
        """Map attack chains to MITRE techniques."""
        mapped = []
        
        chain_to_techniques = {
            "brute_force_to_compromise": [
                "T1110", "T1110.001", "T1078", "T1134", "T1059.001", 
                "T1005", "T1041"
            ],
            "credential_theft_lateral": [
                "T1003", "T1003.001", "T1087", "T1018", "T1021", "T1021.001"
            ],
            "malware_execution_exfil": [
                "T1059.001", "T1027", "T1005", "T1560", "T1041"
            ],
        }
        
        for chain in attack_chains:
            tech_ids = chain_to_techniques.get(chain.attack_type, [])
            for tech_id in tech_ids:
                if tech_id in self.techniques:
                    tech_info = self.techniques[tech_id]
                    mapped.append(MitreTechnique(
                        technique_id=tech_id,
                        name=tech_info["name"],
                        tactic=tech_info["tactic"].value,
                        description=tech_info["description"],
                        confidence=min(1.0, max(0.0, chain.correlation_score)),
                        evidence=[f"Attack chain: {chain.description}"],
                        event_ids=[ce.event.event_id for ce in chain.events],
                    ))
        
        return self._merge_mappings(mapped)
    
    def _check_technique_triggers(
        self, 
        events: List[SecurityEvent], 
        triggers: List[str]
    ) -> List[str]:
        """Check if technique triggers are present in events."""
        evidence = []
        
        for event in events:
            event_str = event.event_type.value.lower()
            metadata_str = str({k: v for k, v in event.metadata.items() if v is not False and v is not None}).lower()
            
            for trigger in triggers:
                if trigger.lower() in event_str or trigger.lower() in metadata_str:
                    evidence.append(
                        f"{event.event_type.value}: {trigger} detected "
                        f"(user={event.user}, ip={event.source_ip}, device={event.device})"
                    )
        
        return evidence
    
    def _calculate_confidence(self, evidence: List[str], triggers: List[str]) -> float:
        """Calculate confidence based on evidence."""
        if not evidence:
            return 0.0
        
        # Base confidence on number of unique triggers matched
        unique_triggers = set()
        for e in evidence:
            for t in triggers:
                if t.lower() in e.lower():
                    unique_triggers.add(t)
        
        coverage = len(unique_triggers) / max(1, len(triggers))
        evidence_factor = min(1.0, len(evidence) / 5.0)
        
        return (coverage * 0.7) + (evidence_factor * 0.3)
    
    def get_all_mappings(
        self,
        events: List[SecurityEvent],
        rule_matches: List[RuleMatch],
        attack_chains: List[AttackChain],
    ) -> List[MitreTechnique]:
        """Get comprehensive MITRE mappings from all sources."""
        all_mapped = []
        
        all_mapped.extend(self.map_events(events))
        all_mapped.extend(self.map_rule_matches(rule_matches))
        all_mapped.extend(self.map_attack_chains(attack_chains))
        
        return self._merge_mappings(all_mapped)

    @staticmethod
    def _merge_mappings(mapped):
        """Retain the strongest confidence and all supporting evidence."""
        merged = {}
        for technique in mapped:
            previous = merged.get(technique.technique_id)
            if previous is None:
                merged[technique.technique_id] = replace(
                    technique, evidence=list(technique.evidence), event_ids=list(technique.event_ids))
            else:
                previous.confidence = max(previous.confidence, technique.confidence)
                previous.evidence = list(dict.fromkeys(previous.evidence + technique.evidence))
                previous.event_ids = list(dict.fromkeys(previous.event_ids + technique.event_ids))
        return sorted(merged.values(), key=lambda t: (-t.confidence, t.technique_id))

    def to_dict_list(self, techniques: List[MitreTechnique]) -> List[Dict[str, Any]]:
        """Convert to list of dictionaries for JSON serialization."""
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
                "confidence": t.confidence,
                "evidence": t.evidence,
                "event_ids": t.event_ids,
            }
            for t in techniques
        ]


def map_to_mitre(
    events: List[SecurityEvent],
    rule_matches: List[RuleMatch],
    attack_chains: List[AttackChain],
) -> List[Dict[str, Any]]:
    """Convenience function to map to MITRE ATT&CK."""
    mapper = MitreMapper()
    techniques = mapper.get_all_mappings(events, rule_matches, attack_chains)
    return mapper.to_dict_list(techniques)
