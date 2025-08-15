"""Database operations and schema management for OpenEASD."""

import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
import os

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite database operations for OpenEASD."""
    
    def __init__(self, db_path: str = "data/openeasd.db"):
        self.db_path = db_path
        self._ensure_db_directory()
        self._init_database()
    
    def _ensure_db_directory(self):
        """Ensure database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _init_database(self):
        """Initialize database with required tables."""
        with self.get_connection() as conn:
            self._create_tables(conn)
            self._create_indexes(conn)
            conn.commit()
    
    def _create_tables(self, conn: sqlite3.Connection):
        """Create all required tables."""
        
        # Scan sessions table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                scan_type TEXT NOT NULL CHECK (scan_type IN ('full', 'incremental')),
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')) DEFAULT 'running',
                config_hash TEXT,
                total_findings INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Subdomains table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                subdomain TEXT NOT NULL,
                ip_address TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
                UNIQUE(session_id, subdomain)
            )
        """)
        
        # Services table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                service_name TEXT,
                version TEXT,
                protocol TEXT,
                state TEXT DEFAULT 'open',
                risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')) DEFAULT 'low',
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
                UNIQUE(session_id, host, port, protocol)
            )
        """)
        
        # Vulnerabilities table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                title TEXT,
                description TEXT,
                remediation TEXT,
                cvss_score REAL,
                cve_id TEXT,
                mitre_technique TEXT,
                confidence TEXT DEFAULT 'medium',
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_new BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
            )
        """)
        
        # Alerts table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER,
                session_id INTEGER,
                alert_type TEXT NOT NULL CHECK (alert_type IN ('slack', 'email', 'webhook')),
                severity_threshold TEXT NOT NULL,
                message TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'pending')) DEFAULT 'pending',
                retry_count INTEGER DEFAULT 0,
                error_message TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
            )
        """)
        
        # Scan history for delta detection
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_deltas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                previous_session_id INTEGER,
                change_type TEXT NOT NULL CHECK (change_type IN ('new', 'removed', 'modified')),
                change_category TEXT NOT NULL CHECK (change_category IN ('subdomain', 'service', 'vulnerability')),
                item_identifier TEXT NOT NULL,
                change_details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (previous_session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
            )
        """)
        
        # Configuration table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                config_name TEXT NOT NULL,
                config_data TEXT NOT NULL,  -- JSON string
                config_hash TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(domain, config_name)
            )
        """)
    
    def _create_indexes(self, conn: sqlite3.Connection):
        """Create database indexes for performance."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_scan_sessions_domain ON scan_sessions(domain)",
            "CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status)",
            "CREATE INDEX IF NOT EXISTS idx_scan_sessions_start_time ON scan_sessions(start_time)",
            "CREATE INDEX IF NOT EXISTS idx_subdomains_session ON subdomains(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(subdomain)",
            "CREATE INDEX IF NOT EXISTS idx_services_session ON services(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_services_host_port ON services(host, port)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_session ON vulnerabilities(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON vulnerabilities(host)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_sent_at ON alerts(sent_at)",
            "CREATE INDEX IF NOT EXISTS idx_scan_deltas_session ON scan_deltas(session_id)"
        ]
        
        for index_sql in indexes:
            conn.execute(index_sql)
    
    # Scan session operations
    def create_scan_session(self, domain: str, scan_type: str, config_hash: str = None) -> int:
        """Create new scan session and return session ID."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_sessions (domain, scan_type, config_hash)
                VALUES (?, ?, ?)
            """, (domain, scan_type, config_hash))
            conn.commit()
            return cursor.lastrowid
    
    def update_scan_session(self, session_id: int, status: str = None, 
                           end_time: datetime = None, total_findings: int = None):
        """Update scan session details."""
        updates = []
        params = []
        
        if status:
            updates.append("status = ?")
            params.append(status)
        
        if end_time:
            updates.append("end_time = ?")
            params.append(end_time)
        
        if total_findings is not None:
            updates.append("total_findings = ?")
            params.append(total_findings)
        
        if not updates:
            return
        
        params.append(session_id)
        
        with self.get_connection() as conn:
            conn.execute(f"""
                UPDATE scan_sessions 
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            conn.commit()
    
    def get_scan_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """Get scan session details."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scan_sessions WHERE id = ?
            """, (session_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_latest_session(self, domain: str, scan_type: str = None) -> Optional[Dict[str, Any]]:
        """Get latest scan session for domain."""
        where_clause = "WHERE domain = ?"
        params = [domain]
        
        if scan_type:
            where_clause += " AND scan_type = ?"
            params.append(scan_type)
        
        with self.get_connection() as conn:
            cursor = conn.execute(f"""
                SELECT * FROM scan_sessions 
                {where_clause}
                ORDER BY start_time DESC 
                LIMIT 1
            """, params)
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # Subdomain operations
    def insert_subdomains(self, session_id: int, subdomains: List[Dict[str, Any]]):
        """Insert discovered subdomains."""
        with self.get_connection() as conn:
            conn.executemany("""
                INSERT OR IGNORE INTO subdomains (session_id, subdomain, ip_address)
                VALUES (?, ?, ?)
            """, [(session_id, sub.get('subdomain'), sub.get('ip_address')) 
                  for sub in subdomains])
            conn.commit()
    
    def get_subdomains(self, session_id: int) -> List[Dict[str, Any]]:
        """Get all subdomains for session."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM subdomains WHERE session_id = ?
            """, (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Service operations
    def insert_services(self, session_id: int, services: List[Dict[str, Any]]):
        """Insert discovered services."""
        with self.get_connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO services 
                (session_id, host, port, service_name, version, protocol, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [(session_id, svc.get('host'), svc.get('port'), 
                   svc.get('service_name'), svc.get('version'), 
                   svc.get('protocol'), svc.get('risk_level', 'low')) 
                  for svc in services])
            conn.commit()
    
    def get_services(self, session_id: int) -> List[Dict[str, Any]]:
        """Get all services for session."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM services WHERE session_id = ?
            """, (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Vulnerability operations
    def insert_vulnerabilities(self, session_id: int, vulnerabilities: List[Dict[str, Any]]):
        """Insert discovered vulnerabilities."""
        with self.get_connection() as conn:
            conn.executemany("""
                INSERT INTO vulnerabilities 
                (session_id, host, port, vulnerability_type, severity, title, 
                 description, remediation, cvss_score, cve_id, mitre_technique, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(session_id, vuln.get('host'), vuln.get('port'),
                   vuln.get('vulnerability_type'), vuln.get('severity'),
                   vuln.get('title'), vuln.get('description'),
                   vuln.get('remediation'), vuln.get('cvss_score'),
                   vuln.get('cve_id'), vuln.get('mitre_technique'),
                   vuln.get('confidence', 'medium')) 
                  for vuln in vulnerabilities])
            conn.commit()
    
    def get_vulnerabilities(self, session_id: int, severity: str = None) -> List[Dict[str, Any]]:
        """Get vulnerabilities for session, optionally filtered by severity."""
        where_clause = "WHERE session_id = ?"
        params = [session_id]
        
        if severity:
            where_clause += " AND severity = ?"
            params.append(severity)
        
        with self.get_connection() as conn:
            cursor = conn.execute(f"""
                SELECT * FROM vulnerabilities 
                {where_clause}
                ORDER BY severity DESC, discovered_at DESC
            """, params)
            return [dict(row) for row in cursor.fetchall()]
    
    # Alert operations
    def insert_alert(self, vulnerability_id: int, session_id: int, alert_type: str,
                    severity_threshold: str, message: str) -> int:
        """Insert alert record."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO alerts 
                (vulnerability_id, session_id, alert_type, severity_threshold, message)
                VALUES (?, ?, ?, ?, ?)
            """, (vulnerability_id, session_id, alert_type, severity_threshold, message))
            conn.commit()
            return cursor.lastrowid
    
    def update_alert_status(self, alert_id: int, status: str, error_message: str = None):
        """Update alert delivery status."""
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE alerts 
                SET status = ?, error_message = ?, retry_count = retry_count + 1
                WHERE id = ?
            """, (status, error_message, alert_id))
            conn.commit()
    
    # Delta detection operations
    def insert_scan_delta(self, session_id: int, previous_session_id: int,
                         change_type: str, change_category: str, 
                         item_identifier: str, change_details: str = None):
        """Insert scan delta record."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO scan_deltas 
                (session_id, previous_session_id, change_type, change_category, 
                 item_identifier, change_details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, previous_session_id, change_type, change_category,
                  item_identifier, change_details))
            conn.commit()
    
    def get_scan_deltas(self, session_id: int) -> List[Dict[str, Any]]:
        """Get all changes detected in scan."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scan_deltas 
                WHERE session_id = ?
                ORDER BY created_at DESC
            """, (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Statistics and reporting
    def get_scan_statistics(self, domain: str, days: int = 30) -> Dict[str, Any]:
        """Get scan statistics for domain over specified days."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_scans,
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans,
                    AVG(total_findings) as avg_findings
                FROM scan_sessions 
                WHERE domain = ? AND start_time >= datetime('now', '-{} days')
            """.format(days), (domain,))
            
            stats = dict(cursor.fetchone())
            
            # Get vulnerability trends
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN scan_sessions s ON v.session_id = s.id
                WHERE s.domain = ? AND v.discovered_at >= datetime('now', '-{} days')
                GROUP BY severity
            """.format(days), (domain,))
            
            stats['vulnerability_counts'] = {row['severity']: row['count'] 
                                           for row in cursor.fetchall()}
            
            return stats
    
    def cleanup_old_scans(self, retention_days: int = 90):
        """Clean up old scan data beyond retention period."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM scan_sessions 
                WHERE start_time < datetime('now', '-{} days')
            """.format(retention_days))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            logger.info(f"Cleaned up {deleted_count} old scan sessions")
            return deleted_count
    
    async def initialize(self):
        """Initialize database for async usage."""
        try:
            # Test database connection
            with self.get_connection() as conn:
                cursor = conn.execute("SELECT 1")
                cursor.fetchone()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    async def close(self):
        """Close database connections."""
        # SQLite connections are closed automatically in context manager
        logger.info("Database connections closed")
    
    def is_connected(self) -> bool:
        """Check if database is accessible."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("SELECT 1")
                cursor.fetchone()
            return True
        except Exception:
            return False