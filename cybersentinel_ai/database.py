"""Optional MySQL persistence for CyberSentinel analysis results.

The analysis engine remains usable without MySQL. Set DB_HOST, DB_PORT, DB_NAME,
DB_USER, and DB_PASSWORD, install mysql-connector-python, and call persist_result.
"""

import json
import os
from contextlib import contextmanager
from typing import Any, Iterator
from uuid import UUID, NAMESPACE_URL, uuid5


class DatabaseConfig:
    """Database connection settings read from environment variables."""

    def __init__(self) -> None:
        self.host = os.getenv("DB_HOST", "127.0.0.1")
        self.port = int(os.getenv("DB_PORT", "3306"))
        self.database = os.getenv("DB_NAME", "cybersentinel")
        self.user = os.getenv("DB_USER", "cybersentinel_app")
        self.password = os.getenv("DB_PASSWORD", "")


class CyberSentinelRepository:
    """Persist normalized events and the resulting incident evidence."""

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        self.config = config or DatabaseConfig()

    @contextmanager
    def connection(self) -> Iterator[Any]:
        try:
            import mysql.connector
        except ImportError as exc:
            raise RuntimeError("Install mysql-connector-python to use MySQL persistence") from exc
        connection = mysql.connector.connect(
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password,
        )
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def persist_result(self, result: dict[str, Any]) -> dict[str, int]:
        """Store events and incidents from a CyberSentinel result dictionary."""
        stored_events = 0
        stored_incidents = 0
        with self.connection() as connection:
            cursor = connection.cursor()
            for incident in result.get("incidents", []):
                incident_uuid = _uuid_value(incident.get("incident_id"))
                events = incident.get("events", [])
                first_seen = _event_time(events, first=True)
                last_seen = _event_time(events, first=False)
                cursor.execute(
                    """INSERT INTO incidents
                    (incident_uuid, title, attack_type, severity, risk_score, status,
                     description, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, 'NEW', %s, %s, %s)
                    ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP(6)""",
                    (incident_uuid, incident.get("attack_type", "Unknown"),
                     incident.get("attack_type", "Unknown"), incident["severity"],
                     incident["risk_score"], json.dumps(incident.get("evidence", [])),
                     first_seen, last_seen),
                )
                stored_incidents += 1
                cursor.execute("SELECT id FROM incidents WHERE incident_uuid = %s", (incident_uuid,))
                incident_db_id = cursor.fetchone()[0]
                for event in events:
                    event_db_id = self._upsert_event(cursor, event)
                    cursor.execute(
                        """INSERT IGNORE INTO incident_events
                        (incident_id, event_id, relationship_type) VALUES (%s, %s, 'evidence')""",
                        (incident_db_id, event_db_id),
                    )
                    stored_events += 1
            cursor.close()
        return {"incidents": stored_incidents, "events": stored_events}

    @staticmethod
    def _upsert_event(cursor: Any, event: dict[str, Any]) -> int:
        cursor.execute(
            """INSERT INTO security_events
            (event_uuid, event_timestamp, source, event_type, username, source_ip,
             destination_ip, action, severity, raw_message, metadata_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)""",
            (event.get("event_id"), event["timestamp"], event["source"],
             event["event_type"], event.get("user"), event.get("source_ip"),
             event.get("destination_ip"), event.get("action"), "LOW",
             json.dumps(event.get("raw_event")), json.dumps(event.get("metadata", {}))),
        )
        return cursor.lastrowid


def _uuid_value(value: str | None) -> str:
    try:
        return str(UUID(value)) if value else str(UUID(int=0))
    except (ValueError, AttributeError):
        return str(uuid5(NAMESPACE_URL, f"cybersentinel:incident:{value or 'unknown'}"))


def _event_time(events: list[dict[str, Any]], first: bool) -> str:
    timestamps = [event["timestamp"] for event in events if event.get("timestamp")]
    return (min(timestamps) if first else max(timestamps)) if timestamps else "1970-01-01 00:00:00"
