"""Shared behavioral indicators."""
from ipaddress import ip_address


def is_external_ip(value):
    try:
        return ip_address(value).is_global
    except (ValueError, TypeError):
        return False


def is_sensitive_file(value):
    return any(word in str(value).lower() for word in (
        "password", "secret", "key", "shadow", "id_rsa", "config",
        "salary", "salaries", "payroll", "customer", "finance", "\\hr\\", "/hr/",
    ))
