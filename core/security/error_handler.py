#!/usr/bin/env python3
"""
Enterprise Error Handling Framework
Advanced error handling with enterprise-grade security features

Features:
- Secure error handling with sanitization
- Error classification and routing
- Security incident detection from errors
- Error rate limiting and circuit breakers
- Structured logging with correlation IDs
- Error analytics and pattern detection
- Automated error response and mitigation
"""

import os
import sys
import json
import time
import hashlib
import secrets
import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import threading
from functools import wraps

from config import Config

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for classification"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    SECURITY = "security"
    SYSTEM = "system"
    NETWORK = "network"
    DATABASE = "database"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"

@dataclass
class ErrorInfo:
    """Structured error information"""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    sanitized_message: str
    exception_type: str
    stack_trace: Optional[str]
    context: Dict[str, Any]
    correlation_id: Optional[str]
    user_id: Optional[str]
    ip_address: Optional[str]
    metadata: Dict[str, Any]

@dataclass
class ErrorPattern:
    """Error pattern for detection"""
    pattern_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    severity: ErrorSeverity
    response_actions: List[str]

class CircuitBreaker:
    """Circuit breaker for error handling"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.Lock()
    
    def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == 'OPEN':
                if self._should_attempt_reset():
                    self.state = 'HALF_OPEN'
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure()
                raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if self.last_failure_time is None:
            return True
        
        return (time.time() - self.last_failure_time) >= self.recovery_timeout
    
    def _on_success(self):
        """Handle successful operation"""
        self.failure_count = 0
        self.state = 'CLOSED'
    
    def _on_failure(self):
        """Handle failed operation"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'

class EnterpriseErrorHandler:
    """
    Enterprise-grade error handling and security incident detection
    
    This class provides comprehensive error handling including:
    - Secure error sanitization and logging
    - Error pattern detection and classification
    - Security incident detection from error patterns
    - Rate limiting and circuit breaker protection
    - Automated error response and mitigation
    - Error analytics and reporting
    """
    
    def __init__(self):
        """Initialize enterprise error handler"""
        self.error_store = deque(maxlen=10000)  # Keep last 10k errors
        self.error_patterns = self._load_error_patterns()
        self.rate_limiters = defaultdict(lambda: deque(maxlen=100))
        self.circuit_breakers = {}
        
        # Error classification rules
        self.classification_rules = self._initialize_classification_rules()
        
        # Security incident thresholds
        self.security_thresholds = {
            'authentication_failures': 10,  # per 5 minutes
            'authorization_failures': 5,    # per 5 minutes
            'input_validation_errors': 20,  # per 5 minutes
            'security_errors': 3            # per 5 minutes
        }
        
        # Sanitization patterns
        self.sanitization_patterns = self._load_sanitization_patterns()
        
        logger.info("Enterprise Error Handler initialized")
    
    def handle_error(self, exception: Exception, context: Dict[str, Any] = None,
                    correlation_id: str = None, user_id: str = None,
                    ip_address: str = None) -> ErrorInfo:
        """
        Handle error with comprehensive processing
        
        Args:
            exception: Exception to handle
            context: Additional context information
            correlation_id: Request correlation ID
            user_id: User ID if available
            ip_address: Client IP address
            
        Returns:
            ErrorInfo object with processed error information
        """
        context = context or {}
        
        # Generate error ID
        error_id = self._generate_error_id()
        
        # Classify error
        severity, category = self._classify_error(exception, context)
        
        # Sanitize error message
        raw_message = str(exception)
        sanitized_message = self._sanitize_error_message(raw_message, context)
        
        # Get stack trace (if needed)
        stack_trace = None
        if severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            stack_trace = self._get_sanitized_stack_trace(exception)
        
        # Create error info
        error_info = ErrorInfo(
            error_id=error_id,
            timestamp=datetime.utcnow(),
            severity=severity,
            category=category,
            message=raw_message,
            sanitized_message=sanitized_message,
            exception_type=type(exception).__name__,
            stack_trace=stack_trace,
            context=self._sanitize_context(context),
            correlation_id=correlation_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={}
        )
        
        # Store error
        self.error_store.append(error_info)
        
        # Check rate limiting
        self._check_rate_limiting(error_info)
        
        # Detect security incidents
        self._detect_security_incidents(error_info)
        
        # Check error patterns
        self._check_error_patterns(error_info)
        
        # Log error appropriately
        self._log_error(error_info)
        
        # Trigger automated responses
        self._trigger_automated_responses(error_info)
        
        return error_info
    
    def create_error_handler_decorator(self, category: ErrorCategory = None,
                                     severity: ErrorSeverity = None):
        """
        Create decorator for automatic error handling
        
        Args:
            category: Default error category
            severity: Default error severity
            
        Returns:
            Decorator function
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Extract context from function
                    context = {
                        'function': func.__name__,
                        'module': func.__module__,
                        'args_count': len(args),
                        'kwargs_keys': list(kwargs.keys())
                    }
                    
                    # Handle error
                    error_info = self.handle_error(
                        exception=e,
                        context=context
                    )
                    
                    # Re-raise with error ID for tracking
                    e.error_id = error_info.error_id
                    raise
            
            return wrapper
        return decorator
    
    def get_circuit_breaker(self, name: str, failure_threshold: int = 5,
                           recovery_timeout: int = 60) -> CircuitBreaker:
        """
        Get or create circuit breaker
        
        Args:
            name: Circuit breaker name
            failure_threshold: Number of failures before opening
            recovery_timeout: Timeout before attempting recovery
            
        Returns:
            CircuitBreaker instance
        """
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout
            )
        
        return self.circuit_breakers[name]
    
    def get_error_statistics(self, time_window: timedelta = None) -> Dict[str, Any]:
        """
        Get error statistics for analysis
        
        Args:
            time_window: Time window for statistics
            
        Returns:
            Error statistics dictionary
        """
        time_window = time_window or timedelta(hours=24)
        cutoff_time = datetime.utcnow() - time_window
        
        # Filter errors within time window
        recent_errors = [
            error for error in self.error_store
            if error.timestamp >= cutoff_time
        ]
        
        # Calculate statistics
        total_errors = len(recent_errors)
        
        # Group by severity
        severity_counts = defaultdict(int)
        for error in recent_errors:
            severity_counts[error.severity.value] += 1
        
        # Group by category
        category_counts = defaultdict(int)
        for error in recent_errors:
            category_counts[error.category.value] += 1
        
        # Group by exception type
        exception_counts = defaultdict(int)
        for error in recent_errors:
            exception_counts[error.exception_type] += 1
        
        # Calculate error rate (errors per hour)
        hours = max(time_window.total_seconds() / 3600, 1)
        error_rate = total_errors / hours
        
        return {
            'time_window_hours': hours,
            'total_errors': total_errors,
            'error_rate_per_hour': error_rate,
            'severity_breakdown': dict(severity_counts),
            'category_breakdown': dict(category_counts),
            'exception_type_breakdown': dict(exception_counts),
            'circuit_breaker_states': {
                name: cb.state for name, cb in self.circuit_breakers.items()
            }
        }
    
    def search_errors(self, filters: Dict[str, Any] = None,
                     limit: int = 100) -> List[ErrorInfo]:
        """
        Search errors with filters
        
        Args:
            filters: Search filters
            limit: Maximum number of results
            
        Returns:
            List of matching errors
        """
        filters = filters or {}
        results = []
        
        for error in reversed(self.error_store):  # Most recent first
            if len(results) >= limit:
                break
            
            # Apply filters
            if 'severity' in filters and error.severity.value != filters['severity']:
                continue
            
            if 'category' in filters and error.category.value != filters['category']:
                continue
            
            if 'user_id' in filters and error.user_id != filters['user_id']:
                continue
            
            if 'exception_type' in filters and error.exception_type != filters['exception_type']:
                continue
            
            if 'start_time' in filters:
                start_time = datetime.fromisoformat(filters['start_time'])
                if error.timestamp < start_time:
                    continue
            
            if 'end_time' in filters:
                end_time = datetime.fromisoformat(filters['end_time'])
                if error.timestamp > end_time:
                    continue
            
            results.append(error)
        
        return results
    
    def _generate_error_id(self) -> str:
        """Generate unique error ID"""
        timestamp = str(int(time.time()))
        random_part = secrets.token_hex(6)
        return f"err_{timestamp}_{random_part}"
    
    def _classify_error(self, exception: Exception, 
                       context: Dict[str, Any]) -> tuple[ErrorSeverity, ErrorCategory]:
        """Classify error by severity and category"""
        exception_type = type(exception).__name__
        exception_message = str(exception).lower()
        
        # Check classification rules
        for rule in self.classification_rules:
            if self._matches_rule(exception, context, rule):
                return rule['severity'], rule['category']
        
        # Default classification based on exception type
        if exception_type in ['SecurityError', 'PermissionError']:
            return ErrorSeverity.HIGH, ErrorCategory.SECURITY
        elif exception_type in ['AuthenticationError', 'LoginError']:
            return ErrorSeverity.MEDIUM, ErrorCategory.AUTHENTICATION
        elif exception_type in ['ValidationError', 'ValueError']:
            return ErrorSeverity.LOW, ErrorCategory.INPUT_VALIDATION
        elif exception_type in ['DatabaseError', 'ConnectionError']:
            return ErrorSeverity.MEDIUM, ErrorCategory.DATABASE
        elif exception_type in ['SystemError', 'OSError']:
            return ErrorSeverity.HIGH, ErrorCategory.SYSTEM
        else:
            return ErrorSeverity.MEDIUM, ErrorCategory.UNKNOWN
    
    def _matches_rule(self, exception: Exception, context: Dict[str, Any],
                     rule: Dict[str, Any]) -> bool:
        """Check if error matches classification rule"""
        conditions = rule.get('conditions', {})
        
        # Check exception type
        if 'exception_types' in conditions:
            if type(exception).__name__ not in conditions['exception_types']:
                return False
        
        # Check message patterns
        if 'message_patterns' in conditions:
            message = str(exception).lower()
            if not any(pattern in message for pattern in conditions['message_patterns']):
                return False
        
        # Check context conditions
        if 'context_conditions' in conditions:
            for key, expected_value in conditions['context_conditions'].items():
                if context.get(key) != expected_value:
                    return False
        
        return True
    
    def _sanitize_error_message(self, message: str, context: Dict[str, Any]) -> str:
        """Sanitize error message to remove sensitive information"""
        sanitized = message
        
        # Apply sanitization patterns
        for pattern, replacement in self.sanitization_patterns.items():
            import re
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        # Remove potential file paths
        sanitized = re.sub(r'/[^\s]*', '[PATH_REDACTED]', sanitized)
        sanitized = re.sub(r'[A-Z]:\\[^\s]*', '[PATH_REDACTED]', sanitized)
        
        # Remove potential IP addresses
        sanitized = re.sub(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            '[IP_REDACTED]',
            sanitized
        )
        
        # Remove potential email addresses
        sanitized = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            '[EMAIL_REDACTED]',
            sanitized
        )
        
        # Limit message length
        if len(sanitized) > 500:
            sanitized = sanitized[:500] + '... [TRUNCATED]'
        
        return sanitized
    
    def _get_sanitized_stack_trace(self, exception: Exception) -> str:
        """Get sanitized stack trace"""
        try:
            # Get stack trace
            stack_trace = traceback.format_exception(
                type(exception), exception, exception.__traceback__
            )
            
            # Join and sanitize
            full_trace = ''.join(stack_trace)
            
            # Remove sensitive paths
            import re
            sanitized_trace = re.sub(
                r'/[^\s]*/(site-packages|dist-packages)/[^\s]*',
                '[LIBRARY_PATH]',
                full_trace
            )
            
            # Remove absolute paths
            sanitized_trace = re.sub(
                r'/[^\s]*/',
                '[PATH]/',
                sanitized_trace
            )
            
            return sanitized_trace
            
        except Exception:
            return "[STACK_TRACE_UNAVAILABLE]"
    
    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize context information"""
        sanitized = {}
        
        for key, value in context.items():
            # Skip sensitive keys
            if any(sensitive in key.lower() for sensitive in 
                   ['password', 'token', 'secret', 'key', 'auth']):
                sanitized[key] = '[REDACTED]'
                continue
            
            # Sanitize string values
            if isinstance(value, str):
                if len(value) > 200:
                    sanitized[key] = value[:200] + '... [TRUNCATED]'
                else:
                    sanitized[key] = value
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
            elif isinstance(value, (list, tuple)):
                sanitized[key] = f'[{type(value).__name__} with {len(value)} items]'
            elif isinstance(value, dict):
                sanitized[key] = f'[dict with {len(value)} keys]'
            else:
                sanitized[key] = f'[{type(value).__name__}]'
        
        return sanitized
    
    def _check_rate_limiting(self, error_info: ErrorInfo):
        """Check for error rate limiting"""
        key = f"{error_info.category.value}_{error_info.ip_address or 'unknown'}"
        current_time = time.time()
        
        # Add current error
        self.rate_limiters[key].append(current_time)
        
        # Check rate limit (10 errors per minute)
        recent_errors = [
            t for t in self.rate_limiters[key]
            if current_time - t <= 60  # Last minute
        ]
        
        if len(recent_errors) > 10:
            # Trigger rate limiting response
            self._trigger_rate_limit_response(error_info, len(recent_errors))
    
    def _detect_security_incidents(self, error_info: ErrorInfo):
        """Detect potential security incidents from error patterns"""
        if error_info.category not in [
            ErrorCategory.AUTHENTICATION,
            ErrorCategory.AUTHORIZATION,
            ErrorCategory.SECURITY,
            ErrorCategory.INPUT_VALIDATION
        ]:
            return
        
        # Count recent errors of same category
        cutoff_time = datetime.utcnow() - timedelta(minutes=5)
        recent_similar_errors = [
            error for error in self.error_store
            if (error.timestamp >= cutoff_time and 
                error.category == error_info.category and
                error.ip_address == error_info.ip_address)
        ]
        
        threshold = self.security_thresholds.get(
            error_info.category.value,
            5
        )
        
        if len(recent_similar_errors) >= threshold:
            self._trigger_security_incident(error_info, recent_similar_errors)
    
    def _check_error_patterns(self, error_info: ErrorInfo):
        """Check for known error patterns"""
        for pattern in self.error_patterns:
            if self._matches_error_pattern(error_info, pattern):
                self._handle_error_pattern_match(error_info, pattern)
    
    def _matches_error_pattern(self, error_info: ErrorInfo, 
                              pattern: ErrorPattern) -> bool:
        """Check if error matches a known pattern"""
        conditions = pattern.conditions
        
        # Check category
        if 'category' in conditions:
            if error_info.category.value != conditions['category']:
                return False
        
        # Check exception type
        if 'exception_type' in conditions:
            if error_info.exception_type != conditions['exception_type']:
                return False
        
        # Check message patterns
        if 'message_contains' in conditions:
            message = error_info.message.lower()
            if not any(pattern in message for pattern in conditions['message_contains']):
                return False
        
        return True
    
    def _log_error(self, error_info: ErrorInfo):
        """Log error with appropriate level"""
        log_data = {
            'error_id': error_info.error_id,
            'severity': error_info.severity.value,
            'category': error_info.category.value,
            'message': error_info.sanitized_message,
            'exception_type': error_info.exception_type,
            'correlation_id': error_info.correlation_id,
            'user_id': error_info.user_id,
            'ip_address': error_info.ip_address
        }
        
        if error_info.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"CRITICAL ERROR: {json.dumps(log_data)}")
        elif error_info.severity == ErrorSeverity.HIGH:
            logger.error(f"HIGH SEVERITY ERROR: {json.dumps(log_data)}")
        elif error_info.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"MEDIUM SEVERITY ERROR: {json.dumps(log_data)}")
        else:
            logger.info(f"LOW SEVERITY ERROR: {json.dumps(log_data)}")
    
    def _trigger_automated_responses(self, error_info: ErrorInfo):
        """Trigger automated responses based on error"""
        if error_info.severity == ErrorSeverity.CRITICAL:
            # Critical errors might trigger immediate alerts
            self._send_critical_alert(error_info)
        
        if error_info.category == ErrorCategory.SECURITY:
            # Security errors might trigger additional logging
            self._enhance_security_logging(error_info)
    
    def _trigger_rate_limit_response(self, error_info: ErrorInfo, error_count: int):
        """Handle rate limiting response"""
        logger.warning(
            f"Rate limit exceeded: {error_count} {error_info.category.value} "
            f"errors from {error_info.ip_address} in last minute"
        )
        
        # Could trigger IP blocking or other responses here
    
    def _trigger_security_incident(self, error_info: ErrorInfo, 
                                 related_errors: List[ErrorInfo]):
        """Handle security incident detection"""
        incident_id = secrets.token_hex(8)
        
        logger.critical(
            f"SECURITY INCIDENT DETECTED [{incident_id}]: "
            f"{len(related_errors)} {error_info.category.value} errors "
            f"from {error_info.ip_address} in 5 minutes"
        )
        
        # Could trigger automated security responses here
    
    def _handle_error_pattern_match(self, error_info: ErrorInfo, 
                                   pattern: ErrorPattern):
        """Handle error pattern match"""
        logger.info(f"Error pattern matched: {pattern.name} for error {error_info.error_id}")
        
        # Execute response actions
        for action in pattern.response_actions:
            self._execute_response_action(action, error_info)
    
    def _execute_response_action(self, action: str, error_info: ErrorInfo):
        """Execute automated response action"""
        if action == 'alert_admin':
            self._send_admin_alert(error_info)
        elif action == 'increase_logging':
            self._increase_logging_level(error_info)
        elif action == 'circuit_breaker':
            self._activate_circuit_breaker(error_info)
    
    def _send_critical_alert(self, error_info: ErrorInfo):
        """Send critical error alert"""
        # Implementation would send alert via email, Slack, etc.
        logger.critical(f"CRITICAL ALERT: {error_info.error_id}")
    
    def _send_admin_alert(self, error_info: ErrorInfo):
        """Send admin alert"""
        # Implementation would send alert to administrators
        logger.warning(f"ADMIN ALERT: {error_info.error_id}")
    
    def _enhance_security_logging(self, error_info: ErrorInfo):
        """Enhance security logging"""
        # Implementation would increase security logging detail
        logger.info(f"Enhanced security logging for: {error_info.error_id}")
    
    def _increase_logging_level(self, error_info: ErrorInfo):
        """Increase logging level"""
        # Implementation would temporarily increase logging verbosity
        logger.info(f"Increased logging level for: {error_info.error_id}")
    
    def _activate_circuit_breaker(self, error_info: ErrorInfo):
        """Activate circuit breaker"""
        # Implementation would activate circuit breaker for the component
        logger.info(f"Circuit breaker activated for: {error_info.error_id}")
    
    def _initialize_classification_rules(self) -> List[Dict[str, Any]]:
        """Initialize error classification rules"""
        return [
            {
                'conditions': {
                    'exception_types': ['SecurityError', 'PermissionDenied'],
                    'message_patterns': ['unauthorized', 'forbidden', 'access denied']
                },
                'severity': ErrorSeverity.HIGH,
                'category': ErrorCategory.SECURITY
            },
            {
                'conditions': {
                    'exception_types': ['AuthenticationError', 'LoginError'],
                    'message_patterns': ['login failed', 'invalid credentials']
                },
                'severity': ErrorSeverity.MEDIUM,
                'category': ErrorCategory.AUTHENTICATION
            },
            {
                'conditions': {
                    'message_patterns': ['sql injection', 'xss', 'command injection']
                },
                'severity': ErrorSeverity.CRITICAL,
                'category': ErrorCategory.SECURITY
            }
        ]
    
    def _load_error_patterns(self) -> List[ErrorPattern]:
        """Load error patterns for detection"""
        return [
            ErrorPattern(
                pattern_id="auth_brute_force",
                name="Authentication Brute Force",
                description="Multiple authentication failures from same IP",
                conditions={
                    'category': 'authentication',
                    'message_contains': ['failed', 'invalid']
                },
                severity=ErrorSeverity.HIGH,
                response_actions=['alert_admin', 'circuit_breaker']
            ),
            ErrorPattern(
                pattern_id="injection_attempt",
                name="Injection Attack Attempt",
                description="Potential injection attack detected",
                conditions={
                    'message_contains': ['injection', 'malicious', 'exploit']
                },
                severity=ErrorSeverity.CRITICAL,
                response_actions=['alert_admin', 'increase_logging']
            )
        ]
    
    def _load_sanitization_patterns(self) -> Dict[str, str]:
        """Load patterns for error message sanitization"""
        return {
            r'password[=:]\s*\S+': 'password=[REDACTED]',
            r'token[=:]\s*\S+': 'token=[REDACTED]',
            r'api[_-]?key[=:]\s*\S+': 'api_key=[REDACTED]',
            r'secret[=:]\s*\S+': 'secret=[REDACTED]',
            r'auth[=:]\s*\S+': 'auth=[REDACTED]',
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b': '[CARD_NUMBER_REDACTED]',
            r'\b\d{3}-\d{2}-\d{4}\b': '[SSN_REDACTED]'
        }

# Global instance
error_handler = EnterpriseErrorHandler()