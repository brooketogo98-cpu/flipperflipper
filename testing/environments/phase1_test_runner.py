#!/usr/bin/env python3
"""
Phase 1 Comprehensive Test Runner
Executes all Phase 1 security tests with detailed reporting
"""

import os
import sys
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Phase1TestRunner:
    """Comprehensive test runner for Phase 1 security components"""
    
    def __init__(self):
        self.workspace_root = Path(__file__).parent.parent.parent
        self.test_results = {
            'phase': 'Phase 1',
            'start_time': datetime.now().isoformat(),
            'test_suites': {},
            'overall_status': 'PENDING',
            'coverage_report': {},
            'performance_metrics': {},
            'security_metrics': {}
        }
        
    def setup_test_environment(self):
        """Setup isolated test environment"""
        logger.info("Setting up Phase 1 test environment...")
        
        # Install test dependencies
        try:
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 
                str(self.workspace_root / 'requirements_security.txt')
            ], check=True, capture_output=True)
            logger.info("✅ Test dependencies installed")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to install dependencies: {e}")
            return False
        
        # Setup test database
        self._setup_test_database()
        
        # Setup test Redis
        self._setup_test_redis()
        
        return True
    
    def _setup_test_database(self):
        """Setup test database"""
        test_db_path = self.workspace_root / 'testing' / 'test.db'
        test_db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create test database tables
        try:
            from create_email_tables import create_email_tables
            from create_mfa_tables import create_mfa_tables
            
            # Temporarily set test database path
            original_db_path = os.environ.get('DATABASE_PATH')
            os.environ['DATABASE_PATH'] = str(test_db_path)
            
            create_email_tables()
            create_mfa_tables()
            
            if original_db_path:
                os.environ['DATABASE_PATH'] = original_db_path
            
            logger.info("✅ Test database setup complete")
        except Exception as e:
            logger.warning(f"⚠️ Test database setup failed: {e}")
    
    def _setup_test_redis(self):
        """Setup test Redis (or fallback to memory)"""
        try:
            import redis
            client = redis.Redis(host='localhost', port=6379, db=15)  # Use test DB
            client.ping()
            logger.info("✅ Test Redis connection established")
        except Exception as e:
            logger.info("ℹ️ Using in-memory Redis fallback for testing")
    
    def run_unit_tests(self):
        """Run unit tests for all Phase 1 components"""
        logger.info("Running Phase 1 unit tests...")
        
        test_suites = [
            ('Session Manager', 'tests/security/test_session_security.py'),
            ('Input Validator', 'tests/security/test_input_validation.py'),
            # Add more test suites as they're created
        ]
        
        for suite_name, test_path in test_suites:
            logger.info(f"Running {suite_name} tests...")
            
            result = self._run_pytest_suite(test_path, suite_name)
            self.test_results['test_suites'][suite_name] = result
            
            if result['status'] == 'PASSED':
                logger.info(f"✅ {suite_name} tests passed")
            else:
                logger.error(f"❌ {suite_name} tests failed")
    
    def _run_pytest_suite(self, test_path, suite_name):
        """Run a specific pytest suite"""
        full_test_path = self.workspace_root / test_path
        
        if not full_test_path.exists():
            return {
                'status': 'SKIPPED',
                'reason': 'Test file not found',
                'tests_run': 0,
                'failures': 0,
                'coverage': 0
            }
        
        try:
            # Run pytest with coverage
            cmd = [
                sys.executable, '-m', 'pytest',
                str(full_test_path),
                '-v',
                '--tb=short',
                '--cov=core.security',
                '--cov-report=json',
                '--json-report',
                '--json-report-file=/tmp/pytest_report.json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            try:
                with open('/tmp/pytest_report.json', 'r') as f:
                    pytest_data = json.load(f)
                
                return {
                    'status': 'PASSED' if result.returncode == 0 else 'FAILED',
                    'tests_run': pytest_data.get('summary', {}).get('total', 0),
                    'failures': pytest_data.get('summary', {}).get('failed', 0),
                    'duration': pytest_data.get('duration', 0),
                    'coverage': self._extract_coverage(),
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            except Exception:
                return {
                    'status': 'FAILED',
                    'reason': 'Could not parse test results',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'status': 'TIMEOUT',
                'reason': 'Tests exceeded 5 minute timeout'
            }
        except Exception as e:
            return {
                'status': 'ERROR',
                'reason': str(e)
            }
    
    def _extract_coverage(self):
        """Extract coverage information"""
        try:
            with open('coverage.json', 'r') as f:
                coverage_data = json.load(f)
            
            return {
                'total_coverage': coverage_data.get('totals', {}).get('percent_covered', 0),
                'files': len(coverage_data.get('files', {})),
                'missing_lines': coverage_data.get('totals', {}).get('missing_lines', 0)
            }
        except Exception:
            return {'total_coverage': 0}
    
    def run_security_tests(self):
        """Run security-specific tests"""
        logger.info("Running security penetration tests...")
        
        security_tests = [
            self._test_command_injection_prevention,
            self._test_sql_injection_prevention,
            self._test_xss_prevention,
            self._test_session_security,
            self._test_input_validation_bypass,
        ]
        
        security_results = {}
        
        for test_func in security_tests:
            test_name = test_func.__name__
            logger.info(f"Running {test_name}...")
            
            try:
                result = test_func()
                security_results[test_name] = result
                
                if result['passed']:
                    logger.info(f"✅ {test_name} passed")
                else:
                    logger.error(f"❌ {test_name} failed: {result.get('reason', 'Unknown')}")
                    
            except Exception as e:
                logger.error(f"❌ {test_name} error: {e}")
                security_results[test_name] = {
                    'passed': False,
                    'reason': str(e)
                }
        
        self.test_results['security_metrics'] = security_results
    
    def _test_command_injection_prevention(self):
        """Test command injection prevention"""
        from core.security.input_validator import EnterpriseInputValidator, InputType
        
        validator = EnterpriseInputValidator()
        
        # Test malicious commands
        malicious_commands = [
            'ls; rm -rf /',
            'cat /etc/passwd',
            '`whoami`',
            '$(id)',
            'ls && cat /etc/shadow'
        ]
        
        for cmd in malicious_commands:
            result = validator.validate_command(cmd)
            if result.is_valid:
                return {
                    'passed': False,
                    'reason': f'Command injection not detected: {cmd}'
                }
        
        return {'passed': True, 'blocked_commands': len(malicious_commands)}
    
    def _test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        from core.security.input_validator import EnterpriseInputValidator
        
        validator = EnterpriseInputValidator()
        
        # Test malicious SQL
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1 OR '1'='1'",
            "SELECT * FROM users; DROP TABLE users;",
            "SELECT * FROM users WHERE name = 'admin'--"
        ]
        
        for query in malicious_queries:
            result = validator.validate_sql_query(query)
            if result.is_valid:
                return {
                    'passed': False,
                    'reason': f'SQL injection not detected: {query}'
                }
        
        return {'passed': True, 'blocked_queries': len(malicious_queries)}
    
    def _test_xss_prevention(self):
        """Test XSS prevention"""
        from core.security.input_validator import EnterpriseInputValidator, InputType
        
        validator = EnterpriseInputValidator()
        
        # Test XSS payloads
        xss_payloads = [
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            'javascript:alert("xss")'
        ]
        
        for payload in xss_payloads:
            result = validator.validate_input(payload, InputType.HTML_CONTENT)
            if result.is_valid:
                return {
                    'passed': False,
                    'reason': f'XSS not detected: {payload}'
                }
        
        return {'passed': True, 'blocked_payloads': len(xss_payloads)}
    
    def _test_session_security(self):
        """Test session security features"""
        try:
            from core.security.session_manager import EnterpriseSessionManager
            from flask import Flask
            
            app = Flask(__name__)
            app.config['SECRET_KEY'] = 'test-key'
            
            with app.test_request_context():
                session_manager = EnterpriseSessionManager()
                
                # Test session creation
                token, session_info = session_manager.create_session('test_user')
                
                # Test session validation
                validated = session_manager.validate_session(token)
                
                if not validated or validated.user_id != 'test_user':
                    return {
                        'passed': False,
                        'reason': 'Session validation failed'
                    }
                
                # Test session regeneration
                new_result = session_manager.regenerate_session(token)
                if not new_result:
                    return {
                        'passed': False,
                        'reason': 'Session regeneration failed'
                    }
                
                return {'passed': True}
                
        except Exception as e:
            return {
                'passed': False,
                'reason': f'Session security test error: {e}'
            }
    
    def _test_input_validation_bypass(self):
        """Test input validation bypass attempts"""
        from core.security.input_validator import EnterpriseInputValidator, InputType
        
        validator = EnterpriseInputValidator()
        
        # Test bypass attempts
        bypass_attempts = [
            ('email', 'test@example.com<script>alert(1)</script>', InputType.EMAIL),
            ('username', 'admin\x00user', InputType.USERNAME),
            ('url', 'javascript:alert(1)', InputType.URL),
        ]
        
        for test_name, malicious_input, input_type in bypass_attempts:
            result = validator.validate_input(malicious_input, input_type)
            if result.is_valid:
                return {
                    'passed': False,
                    'reason': f'Bypass successful for {test_name}: {malicious_input}'
                }
        
        return {'passed': True, 'bypass_attempts_blocked': len(bypass_attempts)}
    
    def run_performance_tests(self):
        """Run performance tests"""
        logger.info("Running performance tests...")
        
        performance_results = {}
        
        # Test session manager performance
        performance_results['session_manager'] = self._test_session_performance()
        
        # Test input validator performance
        performance_results['input_validator'] = self._test_validation_performance()
        
        self.test_results['performance_metrics'] = performance_results
    
    def _test_session_performance(self):
        """Test session manager performance"""
        try:
            from core.security.session_manager import EnterpriseSessionManager
            from flask import Flask
            import time
            
            app = Flask(__name__)
            app.config['SECRET_KEY'] = 'test-key'
            
            with app.test_request_context():
                session_manager = EnterpriseSessionManager()
                
                # Test session creation performance
                start_time = time.time()
                tokens = []
                
                for i in range(100):
                    token, _ = session_manager.create_session(f'user_{i}')
                    tokens.append(token)
                
                creation_time = time.time() - start_time
                
                # Test session validation performance
                start_time = time.time()
                
                for token in tokens:
                    session_manager.validate_session(token)
                
                validation_time = time.time() - start_time
                
                return {
                    'creation_time_per_session': creation_time / 100,
                    'validation_time_per_session': validation_time / 100,
                    'total_sessions_tested': 100,
                    'passed': creation_time < 10 and validation_time < 5  # Performance thresholds
                }
                
        except Exception as e:
            return {
                'passed': False,
                'error': str(e)
            }
    
    def _test_validation_performance(self):
        """Test input validator performance"""
        try:
            from core.security.input_validator import EnterpriseInputValidator, InputType
            import time
            
            validator = EnterpriseInputValidator()
            
            # Test email validation performance
            start_time = time.time()
            
            for i in range(1000):
                validator.validate_input(f'user_{i}@example.com', InputType.EMAIL)
            
            validation_time = time.time() - start_time
            
            return {
                'validation_time_per_input': validation_time / 1000,
                'total_validations_tested': 1000,
                'passed': validation_time < 5  # Should validate 1000 inputs in under 5 seconds
            }
            
        except Exception as e:
            return {
                'passed': False,
                'error': str(e)
            }
    
    def run_integration_tests(self):
        """Run integration tests between Phase 1 components"""
        logger.info("Running integration tests...")
        
        integration_results = {}
        
        # Test session manager + input validator integration
        integration_results['session_input_integration'] = self._test_session_input_integration()
        
        self.test_results['integration_tests'] = integration_results
    
    def _test_session_input_integration(self):
        """Test integration between session manager and input validator"""
        try:
            from core.security.session_manager import EnterpriseSessionManager
            from core.security.input_validator import EnterpriseInputValidator, InputType
            from flask import Flask
            
            app = Flask(__name__)
            app.config['SECRET_KEY'] = 'test-key'
            
            with app.test_request_context():
                session_manager = EnterpriseSessionManager()
                validator = EnterpriseInputValidator()
                
                # Create session
                token, session_info = session_manager.create_session('test_user')
                
                # Validate user input in session context
                context = {
                    'session_id': session_info.session_id,
                    'user_id': session_info.user_id
                }
                
                result = validator.validate_input(
                    'test@example.com', 
                    InputType.EMAIL, 
                    context
                )
                
                return {
                    'passed': result.is_valid,
                    'session_created': True,
                    'input_validated': True
                }
                
        except Exception as e:
            return {
                'passed': False,
                'error': str(e)
            }
    
    def generate_report(self):
        """Generate comprehensive test report"""
        self.test_results['end_time'] = datetime.now().isoformat()
        self.test_results['duration'] = (
            datetime.fromisoformat(self.test_results['end_time']) - 
            datetime.fromisoformat(self.test_results['start_time'])
        ).total_seconds()
        
        # Determine overall status
        all_passed = True
        
        # Check unit tests
        for suite_name, suite_result in self.test_results['test_suites'].items():
            if suite_result.get('status') != 'PASSED':
                all_passed = False
                break
        
        # Check security tests
        for test_name, test_result in self.test_results.get('security_metrics', {}).items():
            if not test_result.get('passed', False):
                all_passed = False
                break
        
        # Check performance tests
        for test_name, test_result in self.test_results.get('performance_metrics', {}).items():
            if not test_result.get('passed', False):
                all_passed = False
                break
        
        self.test_results['overall_status'] = 'PASSED' if all_passed else 'FAILED'
        
        # Save report
        report_path = self.workspace_root / 'testing' / 'phase1_test_report.json'
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        logger.info(f"Test report saved to: {report_path}")
        
        # Print summary
        self._print_summary()
        
        return self.test_results
    
    def _print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("PHASE 1 TEST SUMMARY")
        print("="*80)
        
        print(f"Overall Status: {self.test_results['overall_status']}")
        print(f"Duration: {self.test_results['duration']:.2f} seconds")
        
        print("\nUnit Tests:")
        for suite_name, result in self.test_results['test_suites'].items():
            status = result.get('status', 'UNKNOWN')
            tests_run = result.get('tests_run', 0)
            failures = result.get('failures', 0)
            coverage = result.get('coverage', {}).get('total_coverage', 0)
            
            print(f"  {suite_name}: {status} ({tests_run} tests, {failures} failures, {coverage:.1f}% coverage)")
        
        print("\nSecurity Tests:")
        for test_name, result in self.test_results.get('security_metrics', {}).items():
            status = "PASSED" if result.get('passed', False) else "FAILED"
            print(f"  {test_name}: {status}")
        
        print("\nPerformance Tests:")
        for test_name, result in self.test_results.get('performance_metrics', {}).items():
            status = "PASSED" if result.get('passed', False) else "FAILED"
            print(f"  {test_name}: {status}")
        
        print("\n" + "="*80)
    
    def run_all_tests(self):
        """Run all Phase 1 tests"""
        logger.info("Starting Phase 1 comprehensive test suite...")
        
        # Setup environment
        if not self.setup_test_environment():
            logger.error("Failed to setup test environment")
            return False
        
        # Run all test categories
        self.run_unit_tests()
        self.run_security_tests()
        self.run_performance_tests()
        self.run_integration_tests()
        
        # Generate report
        report = self.generate_report()
        
        return report['overall_status'] == 'PASSED'

def main():
    """Main test runner entry point"""
    runner = Phase1TestRunner()
    success = runner.run_all_tests()
    
    if success:
        logger.info("🎉 All Phase 1 tests passed!")
        sys.exit(0)
    else:
        logger.error("❌ Phase 1 tests failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()