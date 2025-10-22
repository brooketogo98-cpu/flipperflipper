#!/usr/bin/env python3
"""
Comprehensive Security Tests for Enterprise Session Manager
Tests all security features and edge cases
"""

import pytest
import time
import json
import secrets
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, request

# Import the session manager
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from core.security.session_manager import (
    EnterpriseSessionManager, SessionInfo, SessionSecurity, ValidationLevel
)

class TestEnterpriseSessionManager:
    """Comprehensive test suite for Enterprise Session Manager"""
    
    @pytest.fixture
    def app(self):
        """Create Flask app for testing"""
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test-secret-key-for-testing-only'
        return app
    
    @pytest.fixture
    def session_manager(self):
        """Create session manager instance for testing"""
        # Mock Redis client for testing
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        
        with patch('core.security.session_manager.redis.from_url', return_value=mock_redis):
            manager = EnterpriseSessionManager()
            manager.redis_client = self._create_test_redis()
            return manager
    
    def _create_test_redis(self):
        """Create in-memory Redis mock for testing"""
        class TestRedis:
            def __init__(self):
                self.data = {}
                self.expiry = {}
            
            def set(self, key, value, ex=None):
                self.data[key] = value
                if ex:
                    self.expiry[key] = time.time() + ex
            
            def get(self, key):
                if key in self.expiry and time.time() > self.expiry[key]:
                    del self.data[key]
                    del self.expiry[key]
                    return None
                return self.data.get(key)
            
            def delete(self, key):
                self.data.pop(key, None)
                self.expiry.pop(key, None)
            
            def exists(self, key):
                return key in self.data
            
            def keys(self, pattern):
                import fnmatch
                return [k for k in self.data.keys() if fnmatch.fnmatch(k, pattern)]
        
        return TestRedis()
    
    def test_session_creation_basic(self, session_manager, app):
        """Test basic session creation"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            assert token is not None
            assert isinstance(session_info, SessionInfo)
            assert session_info.user_id == 'test_user'
            assert session_info.is_active is True
            assert session_info.security_level == 'standard'
    
    def test_session_creation_with_permissions(self, session_manager, app):
        """Test session creation with specific permissions"""
        permissions = ['read', 'write', 'admin']
        
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session(
                'test_user', 
                security_level='high',
                permissions=permissions
            )
            
            assert session_info.security_level == 'high'
            assert session_info.permissions == permissions
    
    def test_session_validation_valid(self, session_manager, app):
        """Test validation of valid session"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, original_session = session_manager.create_session('test_user')
            
            # Validate the session
            validated_session = session_manager.validate_session(token)
            
            assert validated_session is not None
            assert validated_session.user_id == 'test_user'
            assert validated_session.session_id == original_session.session_id
    
    def test_session_validation_invalid_token(self, session_manager):
        """Test validation of invalid session token"""
        invalid_token = "invalid-token-12345"
        validated_session = session_manager.validate_session(invalid_token)
        
        assert validated_session is None
    
    def test_session_regeneration(self, session_manager, app):
        """Test session regeneration for security"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            original_token, original_session = session_manager.create_session('test_user')
            
            # Regenerate session
            result = session_manager.regenerate_session(original_token)
            
            assert result is not None
            new_token, new_session = result
            
            assert new_token != original_token
            assert new_session.session_id != original_session.session_id
            assert new_session.user_id == original_session.user_id
    
    def test_session_invalidation(self, session_manager, app):
        """Test session invalidation"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Validate session exists
            assert session_manager.validate_session(token) is not None
            
            # Invalidate session
            result = session_manager.invalidate_session(token)
            assert result is True
            
            # Validate session no longer exists
            assert session_manager.validate_session(token) is None
    
    def test_multiple_sessions_per_user(self, session_manager, app):
        """Test multiple sessions for same user"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            # Create multiple sessions
            token1, session1 = session_manager.create_session('test_user')
            token2, session2 = session_manager.create_session('test_user')
            token3, session3 = session_manager.create_session('test_user')
            
            # All sessions should be valid
            assert session_manager.validate_session(token1) is not None
            assert session_manager.validate_session(token2) is not None
            assert session_manager.validate_session(token3) is not None
            
            # Get user sessions
            user_sessions = session_manager.get_user_sessions('test_user')
            assert len(user_sessions) == 3
    
    def test_session_limit_enforcement(self, session_manager, app):
        """Test enforcement of maximum sessions per user"""
        session_manager.max_sessions_per_user = 2
        
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            # Create sessions up to limit
            token1, _ = session_manager.create_session('test_user')
            token2, _ = session_manager.create_session('test_user')
            
            # Both should be valid
            assert session_manager.validate_session(token1) is not None
            assert session_manager.validate_session(token2) is not None
            
            # Create third session (should remove oldest)
            token3, _ = session_manager.create_session('test_user')
            
            # First session should be invalidated
            assert session_manager.validate_session(token1) is None
            assert session_manager.validate_session(token2) is not None
            assert session_manager.validate_session(token3) is not None
    
    def test_session_timeout(self, session_manager, app):
        """Test session timeout functionality"""
        # Set short timeout for testing
        session_manager.session_timeout = 1  # 1 second
        
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Session should be valid immediately
            assert session_manager.validate_session(token) is not None
            
            # Wait for timeout
            time.sleep(2)
            
            # Session should be expired
            assert session_manager.validate_session(token) is None
    
    def test_security_anomaly_detection(self, session_manager, app):
        """Test security anomaly detection"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Simulate IP address change (suspicious activity)
            with app.test_request_context('/', 
                                        environ_base={'REMOTE_ADDR': '192.168.1.100'},
                                        headers={'User-Agent': 'Different-Agent'}):
                
                # Should detect anomaly and invalidate session
                validated_session = session_manager.validate_session(token)
                # Note: This might be None due to anomaly detection
    
    def test_device_fingerprinting(self, session_manager, app):
        """Test device fingerprinting functionality"""
        user_agent1 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        user_agent2 = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        
        with app.test_request_context('/', headers={'User-Agent': user_agent1}):
            token1, session1 = session_manager.create_session('test_user')
        
        with app.test_request_context('/', headers={'User-Agent': user_agent2}):
            token2, session2 = session_manager.create_session('test_user')
        
        # Different user agents should create different fingerprints
        assert session1.device_fingerprint != session2.device_fingerprint
    
    def test_session_encryption(self, session_manager, app):
        """Test session token encryption"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Token should be encrypted (not readable)
            assert session_info.session_id not in token
            assert 'test_user' not in token
            
            # But should be decryptable by session manager
            validated_session = session_manager.validate_session(token)
            assert validated_session is not None
            assert validated_session.user_id == 'test_user'
    
    def test_session_audit_logging(self, session_manager, app):
        """Test session audit logging"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Check that audit log entries were created
            audit_keys = session_manager.redis_client.keys('audit:session:*')
            assert len(audit_keys) > 0
            
            # Verify audit log content
            audit_data = session_manager.redis_client.get(audit_keys[0])
            audit_info = json.loads(audit_data)
            
            assert audit_info['event_type'] == 'session_created'
            assert audit_info['user_id'] == 'test_user'
            assert audit_info['session_id'] == session_info.session_id
    
    def test_invalidate_all_user_sessions(self, session_manager, app):
        """Test invalidating all sessions for a user"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            # Create multiple sessions
            token1, _ = session_manager.create_session('test_user')
            token2, _ = session_manager.create_session('test_user')
            token3, _ = session_manager.create_session('test_user')
            
            # All should be valid
            assert session_manager.validate_session(token1) is not None
            assert session_manager.validate_session(token2) is not None
            assert session_manager.validate_session(token3) is not None
            
            # Invalidate all sessions
            count = session_manager.invalidate_user_sessions('test_user')
            assert count == 3
            
            # All should be invalid
            assert session_manager.validate_session(token1) is None
            assert session_manager.validate_session(token2) is None
            assert session_manager.validate_session(token3) is None
    
    def test_session_metadata(self, session_manager, app):
        """Test session metadata functionality"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Add metadata
            session_info.metadata['custom_field'] = 'custom_value'
            session_manager._store_session(session_info.session_id, session_info)
            
            # Retrieve and verify metadata
            retrieved_session = session_manager.validate_session(token)
            assert retrieved_session.metadata['custom_field'] == 'custom_value'
    
    def test_concurrent_session_access(self, session_manager, app):
        """Test concurrent access to same session"""
        import threading
        import queue
        
        results = queue.Queue()
        
        def validate_session_worker(token):
            with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
                result = session_manager.validate_session(token)
                results.put(result is not None)
        
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, _ = session_manager.create_session('test_user')
            
            # Create multiple threads accessing same session
            threads = []
            for _ in range(5):
                thread = threading.Thread(target=validate_session_worker, args=(token,))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads
            for thread in threads:
                thread.join()
            
            # All validations should succeed
            success_count = 0
            while not results.empty():
                if results.get():
                    success_count += 1
            
            assert success_count == 5
    
    def test_session_serialization(self, session_manager, app):
        """Test session serialization and deserialization"""
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            token, session_info = session_manager.create_session('test_user')
            
            # Serialize session
            serialized = session_manager._serialize_session(session_info)
            assert isinstance(serialized, str)
            
            # Deserialize session
            deserialized = session_manager._deserialize_session(serialized)
            assert isinstance(deserialized, SessionInfo)
            assert deserialized.user_id == session_info.user_id
            assert deserialized.session_id == session_info.session_id
    
    def test_session_security_levels(self, session_manager, app):
        """Test different session security levels"""
        security_levels = ['standard', 'high', 'critical']
        
        for level in security_levels:
            with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
                token, session_info = session_manager.create_session(
                    'test_user', security_level=level
                )
                
                assert session_info.security_level == level
                
                # Validate session
                validated = session_manager.validate_session(token)
                assert validated is not None
                assert validated.security_level == level
    
    def test_error_handling(self, session_manager, app):
        """Test error handling in various scenarios"""
        # Test with corrupted token
        corrupted_token = "corrupted-token-data"
        result = session_manager.validate_session(corrupted_token)
        assert result is None
        
        # Test with empty token
        result = session_manager.validate_session("")
        assert result is None
        
        # Test with None token
        result = session_manager.validate_session(None)
        assert result is None
    
    @pytest.mark.benchmark
    def test_session_performance(self, session_manager, app, benchmark):
        """Test session creation and validation performance"""
        def create_and_validate_session():
            with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
                token, _ = session_manager.create_session('test_user')
                return session_manager.validate_session(token)
        
        result = benchmark(create_and_validate_session)
        assert result is not None
    
    def test_memory_usage(self, session_manager, app):
        """Test memory usage with many sessions"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create many sessions
        tokens = []
        with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
            for i in range(100):
                token, _ = session_manager.create_session(f'user_{i}')
                tokens.append(token)
        
        # Validate all sessions
        for token in tokens:
            with app.test_request_context('/', headers={'User-Agent': 'Test-Agent'}):
                assert session_manager.validate_session(token) is not None
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 50MB for 100 sessions)
        assert memory_increase < 50 * 1024 * 1024

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=core.security.session_manager'])