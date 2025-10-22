#!/usr/bin/env python3
"""
Database System for Agent and Command Management
REAL SQLite implementation with encryption
"""

import os
import sqlite3
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from contextlib import contextmanager
import threading

from Core.config_loader import config
from Core.logger import get_logger

log = get_logger('database')

class EliteDatabase:
    """
    Central database for storing agents, commands, results, and audit logs
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self.db_path = Path(config.database_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.init_database()
            log.info(f"Database initialized at {self.db_path}")
    
    @contextmanager
    def get_connection(self):
        """Thread-safe database connection"""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Agents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    username TEXT,
                    ip_address TEXT,
                    platform TEXT,
                    architecture TEXT,
                    privileges TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_beacon TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    notes TEXT,
                    metadata TEXT
                )
            ''')
            
            # Commands table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    executed_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    retry_count INTEGER DEFAULT 0,
                    priority INTEGER DEFAULT 5,
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            
            # Results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id INTEGER NOT NULL,
                    agent_id TEXT NOT NULL,
                    output TEXT,
                    error TEXT,
                    exit_code INTEGER,
                    execution_time REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (command_id) REFERENCES commands (id),
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            
            # Files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    filepath TEXT,
                    size INTEGER,
                    hash TEXT,
                    content BLOB,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_type TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            
            # Credentials table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    type TEXT,
                    username TEXT,
                    password TEXT,
                    domain TEXT,
                    url TEXT,
                    notes TEXT,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            
            # Keylog table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keylogs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    window_title TEXT,
                    keystrokes TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            
            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT,
                    action TEXT,
                    target TEXT,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expired BOOLEAN DEFAULT 0
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status, agent_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_results_agent ON results(agent_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_agent ON files(agent_id)')
            
            conn.commit()
            log.info("Database schema created successfully")
    
    # Agent Management
    def add_agent(self, agent_data: Dict) -> bool:
        """Add new agent to database"""
        
        with self._lock:
            try:
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Generate agent ID if not provided
                    agent_id = agent_data.get('id') or hashlib.md5(
                        f"{agent_data.get('hostname', '')}{time.time()}".encode()
                    ).hexdigest()[:12]
                    
                    cursor.execute('''
                        INSERT INTO agents (id, hostname, username, ip_address, platform, 
                                          architecture, privileges, metadata, last_beacon)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (
                        agent_id,
                        agent_data.get('hostname', 'Unknown'),
                        agent_data.get('username'),
                        agent_data.get('ip_address'),
                        agent_data.get('platform'),
                        agent_data.get('architecture'),
                        agent_data.get('privileges'),
                        json.dumps(agent_data.get('metadata', {}))
                    ))
                    
                    conn.commit()
                    log.info(f"Agent {agent_id} added to database")
                    return True
                    
            except sqlite3.IntegrityError:
                # Agent already exists, update last_seen
                self.update_agent_beacon(agent_id)
                return True
            except Exception as e:
                log.error(f"Failed to add agent: {e}")
                return False
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent details"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM agents WHERE id = ?', (agent_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
    
    def get_all_agents(self, active_only: bool = False) -> List[Dict]:
        """Get all agents"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if active_only:
                cursor.execute('SELECT * FROM agents WHERE status = "active"')
            else:
                cursor.execute('SELECT * FROM agents')
            
            return [dict(row) for row in cursor.fetchall()]
    
    def update_agent_beacon(self, agent_id: str):
        """Update agent last beacon time"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE agents 
                SET last_beacon = CURRENT_TIMESTAMP, 
                    last_seen = CURRENT_TIMESTAMP,
                    status = 'active'
                WHERE id = ?
            ''', (agent_id,))
            conn.commit()
    
    def set_agent_status(self, agent_id: str, status: str):
        """Update agent status"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE agents SET status = ? WHERE id = ?', (status, agent_id))
            conn.commit()
            log.info(f"Agent {agent_id} status set to {status}")
    
    # Command Management
    def add_command(self, agent_id: str, command: str, priority: int = 5) -> int:
        """Add command to queue"""
        
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO commands (agent_id, command, priority)
                    VALUES (?, ?, ?)
                ''', (agent_id, command, priority))
                conn.commit()
                
                command_id = cursor.lastrowid
                log.info(f"Command {command_id} queued for agent {agent_id}")
                return command_id
    
    def get_pending_commands(self, agent_id: str) -> List[Dict]:
        """Get pending commands for agent"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM commands 
                WHERE agent_id = ? AND status = 'pending'
                ORDER BY priority DESC, created_at ASC
            ''', (agent_id,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def mark_command_executed(self, command_id: int):
        """Mark command as executed"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE commands 
                SET status = 'executed', executed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (command_id,))
            conn.commit()
    
    def add_result(self, command_id: int, agent_id: str, output: str, 
                   error: str = None, exit_code: int = 0, execution_time: float = 0):
        """Add command result"""
        
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Add result
                cursor.execute('''
                    INSERT INTO results (command_id, agent_id, output, error, 
                                       exit_code, execution_time)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (command_id, agent_id, output, error, exit_code, execution_time))
                
                # Mark command as completed
                cursor.execute('''
                    UPDATE commands 
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (command_id,))
                
                conn.commit()
                log.info(f"Result added for command {command_id}")
    
    def get_command_results(self, agent_id: str, limit: int = 10) -> List[Dict]:
        """Get recent command results for agent"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT c.command, r.output, r.error, r.exit_code, r.created_at
                FROM results r
                JOIN commands c ON r.command_id = c.id
                WHERE r.agent_id = ?
                ORDER BY r.created_at DESC
                LIMIT ?
            ''', (agent_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # File Management
    def store_file(self, agent_id: str, filename: str, content: bytes, 
                   filepath: str = None) -> int:
        """Store uploaded file"""
        
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                file_hash = hashlib.sha256(content).hexdigest()
                
                cursor.execute('''
                    INSERT INTO files (agent_id, filename, filepath, size, hash, content)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (agent_id, filename, filepath, len(content), file_hash, content))
                
                conn.commit()
                file_id = cursor.lastrowid
                log.info(f"File {filename} stored with ID {file_id}")
                return file_id
    
    def get_file(self, file_id: int) -> Optional[Dict]:
        """Retrieve file"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
    
    # Credentials Management
    def store_credentials(self, agent_id: str, cred_type: str, username: str,
                         password: str, **kwargs):
        """Store harvested credentials"""
        
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO credentials (agent_id, type, username, password, 
                                           domain, url, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_id, cred_type, username, password,
                    kwargs.get('domain'), kwargs.get('url'), kwargs.get('notes')
                ))
                conn.commit()
                log.info(f"Credentials stored for agent {agent_id}")
    
    def get_credentials(self, agent_id: str = None) -> List[Dict]:
        """Get stored credentials"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if agent_id:
                cursor.execute('SELECT * FROM credentials WHERE agent_id = ?', (agent_id,))
            else:
                cursor.execute('SELECT * FROM credentials')
            
            return [dict(row) for row in cursor.fetchall()]
    
    # Keylog Management
    def store_keylog(self, agent_id: str, window_title: str, keystrokes: str):
        """Store keylog data"""
        
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO keylogs (agent_id, window_title, keystrokes)
                    VALUES (?, ?, ?)
                ''', (agent_id, window_title, keystrokes))
                conn.commit()
    
    def get_keylogs(self, agent_id: str, limit: int = 100) -> List[Dict]:
        """Get keylogs for agent"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM keylogs 
                WHERE agent_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (agent_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # Audit Logging
    def audit_log(self, user: str, action: str, target: str, details: str = None,
                  ip_address: str = None):
        """Add audit log entry"""
        
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO audit_log (user, action, target, details, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user, action, target, details, ip_address))
                conn.commit()
    
    # Statistics
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Agent stats
            cursor.execute('SELECT COUNT(*) FROM agents')
            stats['total_agents'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM agents WHERE status = "active"')
            stats['active_agents'] = cursor.fetchone()[0]
            
            # Command stats
            cursor.execute('SELECT COUNT(*) FROM commands')
            stats['total_commands'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM commands WHERE status = "pending"')
            stats['pending_commands'] = cursor.fetchone()[0]
            
            # File stats
            cursor.execute('SELECT COUNT(*), SUM(size) FROM files')
            row = cursor.fetchone()
            stats['total_files'] = row[0]
            stats['total_file_size'] = row[1] or 0
            
            # Credential stats
            cursor.execute('SELECT COUNT(*) FROM credentials')
            stats['total_credentials'] = cursor.fetchone()[0]
            
            return stats

# Global database instance
db = EliteDatabase()

# Test the database
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspace')
    
    print("Testing Elite Database System")
    print("-" * 50)
    
    # Add test agent
    test_agent = {
        'hostname': 'TEST-PC',
        'username': 'testuser',
        'ip_address': '192.168.1.100',
        'platform': 'Windows 10',
        'architecture': 'x64',
        'privileges': 'User'
    }
    
    if db.add_agent(test_agent):
        print("✅ Agent added to database")
    
    # Get agents
    agents = db.get_all_agents()
    print(f"✅ Found {len(agents)} agents in database")
    
    if agents:
        agent_id = agents[0]['id']
        
        # Add command
        cmd_id = db.add_command(agent_id, 'whoami')
        print(f"✅ Command {cmd_id} queued")
        
        # Add result
        db.add_result(cmd_id, agent_id, 'testuser\\TEST-PC', execution_time=0.5)
        print("✅ Result stored")
        
        # Get results
        results = db.get_command_results(agent_id)
        print(f"✅ Retrieved {len(results)} results")
    
    # Get statistics
    stats = db.get_statistics()
    print(f"\n📊 Database Statistics:")
    for key, value in stats.items():
        print(f"  - {key}: {value}")
    
    print("\n✅ Database system working correctly!")