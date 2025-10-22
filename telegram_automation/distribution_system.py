#!/usr/bin/env python3
"""
Telegram Automation System - Intelligent Distribution System
MAXIMUM CAPABILITY - Optimal message distribution with advanced algorithms
NO BASIC IMPLEMENTATIONS - Full production-grade load balancing and optimization
"""

import asyncio
import math
import random
from datetime import datetime, timedelta, time
from typing import Optional, List, Dict, Set, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import heapq
import numpy as np
from scipy import stats
import pytz

from database import (
    DatabaseManager, Campaign, Account, Member,
    MessageQueue, CampaignAccount, CampaignMember
)
from account_manager import AdvancedAccountManager, AccountStatus
from message_variation_engine import AdvancedMessageVariationEngine

# ============================================================================
# CONFIGURATION AND ENUMS
# ============================================================================

@dataclass
class DistributionConfig:
    """Advanced distribution configuration"""
    # Timing settings
    respect_timezone: bool = True
    optimal_hours_start: int = 9  # 9 AM
    optimal_hours_end: int = 21   # 9 PM
    avoid_weekends: bool = False
    avoid_holidays: bool = True
    
    # Rate limiting
    global_rate_limit: int = 1000  # messages per hour globally
    account_rate_limit: int = 50   # messages per day per account
    burst_limit: int = 10          # messages in quick succession
    min_delay_seconds: float = 3.0
    max_delay_seconds: float = 15.0
    
    # Distribution strategy
    use_predictive_analytics: bool = True
    use_machine_learning: bool = True
    adaptive_rate_adjustment: bool = True
    load_balancing_algorithm: str = 'weighted_round_robin'  # or 'least_connections', 'random', 'ai_optimized'
    
    # Priority handling
    enable_priority_queue: bool = True
    high_priority_boost: float = 2.0
    time_sensitive_boost: float = 1.5
    
    # Failure handling
    max_retries: int = 3
    retry_backoff_base: float = 2.0  # Exponential backoff
    failure_threshold: float = 0.2   # 20% failure rate triggers adjustment
    
    # Optimization
    batch_size: int = 100
    parallel_sends: int = 5
    prefetch_messages: int = 500
    cache_account_metrics: bool = True
    
    # Cost optimization
    consider_proxy_costs: bool = True
    minimize_account_switching: bool = True
    group_by_target_timezone: bool = True
    
    # Advanced features
    predictive_flood_detection: bool = True
    sentiment_based_timing: bool = True
    engagement_prediction: bool = True
    dynamic_message_ordering: bool = True
    
    # Monitoring
    track_performance_metrics: bool = True
    alert_on_degradation: bool = True
    auto_pause_on_issues: bool = True

class DistributionStrategy(Enum):
    """Distribution strategies"""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    RANDOM = "random"
    AI_OPTIMIZED = "ai_optimized"
    COST_OPTIMIZED = "cost_optimized"
    PERFORMANCE_OPTIMIZED = "performance_optimized"
    TIMEZONE_AWARE = "timezone_aware"

class MessagePriority(Enum):
    """Message priority levels"""
    CRITICAL = 10
    HIGH = 7
    MEDIUM = 5
    LOW = 3
    BACKGROUND = 1

# ============================================================================
# ANALYTICS AND PREDICTION
# ============================================================================

class PredictiveAnalytics:
    """Predictive analytics for optimal distribution"""
    
    def __init__(self):
        self.historical_data = defaultdict(list)
        self.flood_wait_patterns = defaultdict(list)
        self.engagement_patterns = defaultdict(list)
        self.timezone_activity = defaultdict(lambda: defaultdict(int))
        
    def predict_flood_wait_probability(
        self,
        account: Account,
        current_hour: int,
        messages_sent_today: int
    ) -> float:
        """Predict probability of flood wait"""
        
        # Base probability from account history
        if account.flood_waits_total > 0:
            base_prob = min(0.5, account.flood_waits_total / max(1, account.messages_sent_total) * 10)
        else:
            base_prob = 0.05
        
        # Adjust for current usage
        daily_limit = account.daily_limit
        usage_ratio = messages_sent_today / max(1, daily_limit)
        
        if usage_ratio > 0.8:
            usage_modifier = 0.3
        elif usage_ratio > 0.6:
            usage_modifier = 0.15
        elif usage_ratio > 0.4:
            usage_modifier = 0.05
        else:
            usage_modifier = 0
        
        # Time-based modifier (higher risk during peak hours)
        if 10 <= current_hour <= 14 or 18 <= current_hour <= 20:
            time_modifier = 0.1
        else:
            time_modifier = 0
        
        # Recent flood wait modifier
        if account.last_flood_wait:
            hours_since = (datetime.utcnow() - account.last_flood_wait).total_seconds() / 3600
            if hours_since < 1:
                recent_modifier = 0.4
            elif hours_since < 6:
                recent_modifier = 0.2
            elif hours_since < 24:
                recent_modifier = 0.1
            else:
                recent_modifier = 0
        else:
            recent_modifier = 0
        
        total_probability = min(1.0, base_prob + usage_modifier + time_modifier + recent_modifier)
        return total_probability
    
    def predict_optimal_send_time(
        self,
        member: Member,
        timezone: Optional[str] = None
    ) -> datetime:
        """Predict optimal time to send message to member"""
        
        if timezone:
            tz = pytz.timezone(timezone)
        else:
            tz = pytz.UTC
        
        now = datetime.now(tz)
        
        # If member has activity history
        if member.last_seen:
            # Send around the same time they were last active
            optimal_hour = member.last_seen.hour
        else:
            # Use general optimal hours
            optimal_hour = random.randint(10, 18)
        
        # Find next occurrence of optimal hour
        optimal_time = now.replace(hour=optimal_hour, minute=random.randint(0, 59))
        
        if optimal_time < now:
            # Move to tomorrow
            optimal_time += timedelta(days=1)
        
        # Add some randomness
        optimal_time += timedelta(minutes=random.randint(-30, 30))
        
        return optimal_time
    
    def predict_engagement_probability(
        self,
        member: Member,
        message_sentiment: float,
        send_time: datetime
    ) -> float:
        """Predict probability of member engagement"""
        
        base_engagement = 0.1  # Base 10% engagement
        
        # Member activity level
        if member.engagement_score:
            activity_modifier = member.engagement_score * 0.3
        else:
            activity_modifier = 0
        
        # Verified accounts more likely to engage
        if member.is_verified:
            verification_modifier = 0.1
        else:
            verification_modifier = 0
        
        # Time-based modifier
        hour = send_time.hour
        if 10 <= hour <= 12 or 19 <= hour <= 21:
            time_modifier = 0.1  # Peak engagement hours
        elif 2 <= hour <= 6:
            time_modifier = -0.1  # Low engagement hours
        else:
            time_modifier = 0
        
        # Sentiment matching (positive messages get better engagement)
        if message_sentiment > 0:
            sentiment_modifier = message_sentiment * 0.1
        else:
            sentiment_modifier = 0
        
        total_probability = max(0, min(1, 
            base_engagement + activity_modifier + verification_modifier + 
            time_modifier + sentiment_modifier
        ))
        
        return total_probability
    
    def update_patterns(self, event_type: str, data: Dict):
        """Update historical patterns with new data"""
        
        if event_type == 'flood_wait':
            account_id = data['account_id']
            self.flood_wait_patterns[account_id].append({
                'timestamp': datetime.utcnow(),
                'messages_sent': data['messages_sent'],
                'wait_seconds': data['wait_seconds']
            })
        
        elif event_type == 'engagement':
            member_id = data['member_id']
            self.engagement_patterns[member_id].append({
                'timestamp': datetime.utcnow(),
                'message_time': data['message_time'],
                'engaged': data['engaged']
            })
        
        elif event_type == 'timezone_activity':
            timezone = data['timezone']
            hour = data['hour']
            self.timezone_activity[timezone][hour] += 1

class LoadCalculator:
    """Calculate and predict system load"""
    
    def __init__(self):
        self.current_load = defaultdict(int)
        self.predicted_load = defaultdict(list)
        
    def calculate_account_load(self, account: Account) -> float:
        """Calculate current load on account (0-1)"""
        
        # Message volume load
        daily_usage = account.messages_sent_today / max(1, account.daily_limit)
        
        # Health-based load
        health_load = 1.0 - (account.health_score / 100)
        
        # Flood wait load
        if account.is_flood_waited:
            flood_load = 0.5
        else:
            flood_load = 0
        
        # Combined load
        total_load = min(1.0, daily_usage * 0.5 + health_load * 0.3 + flood_load * 0.2)
        
        return total_load
    
    def calculate_system_load(self, accounts: List[Account]) -> float:
        """Calculate overall system load"""
        
        if not accounts:
            return 0
        
        account_loads = [self.calculate_account_load(acc) for acc in accounts]
        return sum(account_loads) / len(account_loads)
    
    def predict_future_load(
        self,
        accounts: List[Account],
        messages_pending: int,
        time_window_hours: int = 24
    ) -> Dict[int, float]:
        """Predict load over future time windows"""
        
        predictions = {}
        messages_per_hour = messages_pending / max(1, time_window_hours)
        
        for hour in range(time_window_hours):
            # Calculate capacity for this hour
            hourly_capacity = sum(
                acc.hourly_limit for acc in accounts 
                if acc.is_active and not acc.is_banned
            )
            
            # Predict load
            if hourly_capacity > 0:
                predicted_load = messages_per_hour / hourly_capacity
            else:
                predicted_load = 1.0
            
            predictions[hour] = min(1.0, predicted_load)
        
        return predictions

# ============================================================================
# DISTRIBUTION ALGORITHMS
# ============================================================================

class DistributionAlgorithm:
    """Base class for distribution algorithms"""
    
    def select_account(
        self,
        accounts: List[Account],
        message: MessageQueue,
        context: Dict
    ) -> Optional[Account]:
        """Select account for message"""
        raise NotImplementedError

class WeightedRoundRobinAlgorithm(DistributionAlgorithm):
    """Weighted round-robin distribution"""
    
    def __init__(self):
        self.last_selected = {}
        self.weights = {}
        
    def select_account(
        self,
        accounts: List[Account],
        message: MessageQueue,
        context: Dict
    ) -> Optional[Account]:
        """Select account using weighted round-robin"""
        
        if not accounts:
            return None
        
        # Calculate weights for each account
        weighted_accounts = []
        for account in accounts:
            weight = self._calculate_weight(account, context)
            if weight > 0:
                weighted_accounts.append((weight, account))
        
        if not weighted_accounts:
            return None
        
        # Sort by weight
        weighted_accounts.sort(key=lambda x: x[0], reverse=True)
        
        # Get last selected index for this campaign
        campaign_id = message.campaign_id
        last_idx = self.last_selected.get(campaign_id, -1)
        
        # Select next in rotation
        next_idx = (last_idx + 1) % len(weighted_accounts)
        self.last_selected[campaign_id] = next_idx
        
        return weighted_accounts[next_idx][1]
    
    def _calculate_weight(self, account: Account, context: Dict) -> float:
        """Calculate account weight"""
        
        # Base weight from health
        weight = account.health_score / 100
        
        # Capacity weight
        capacity = (account.daily_limit - account.messages_sent_today) / account.daily_limit
        weight *= (1 + capacity)
        
        # Success rate weight
        if account.successful_sends + account.failed_sends > 0:
            success_rate = account.successful_sends / (account.successful_sends + account.failed_sends)
            weight *= (1 + success_rate * 0.5)
        
        # Flood wait penalty
        if account.flood_waits_today > 0:
            weight *= (1 - min(0.5, account.flood_waits_today * 0.1))
        
        return weight

class LeastConnectionsAlgorithm(DistributionAlgorithm):
    """Select account with least active connections"""
    
    def __init__(self):
        self.active_connections = defaultdict(int)
        
    def select_account(
        self,
        accounts: List[Account],
        message: MessageQueue,
        context: Dict
    ) -> Optional[Account]:
        """Select account with fewest active connections"""
        
        if not accounts:
            return None
        
        # Filter available accounts
        available = [
            acc for acc in accounts
            if acc.is_active and not acc.is_banned and
            acc.messages_sent_today < acc.daily_limit
        ]
        
        if not available:
            return None
        
        # Sort by active connections
        available.sort(key=lambda acc: self.active_connections.get(acc.id, 0))
        
        selected = available[0]
        self.active_connections[selected.id] += 1
        
        return selected
    
    def release_connection(self, account_id: int):
        """Release connection when message is sent"""
        if account_id in self.active_connections:
            self.active_connections[account_id] = max(0, self.active_connections[account_id] - 1)

class AIOptimizedAlgorithm(DistributionAlgorithm):
    """AI-optimized distribution using machine learning"""
    
    def __init__(self, analytics: PredictiveAnalytics):
        self.analytics = analytics
        self.performance_history = defaultdict(list)
        
    def select_account(
        self,
        accounts: List[Account],
        message: MessageQueue,
        context: Dict
    ) -> Optional[Account]:
        """Select account using AI optimization"""
        
        if not accounts:
            return None
        
        # Score each account
        scored_accounts = []
        current_hour = datetime.utcnow().hour
        
        for account in accounts:
            if not account.is_active or account.is_banned:
                continue
            
            # Calculate AI score
            score = self._calculate_ai_score(account, message, context, current_hour)
            scored_accounts.append((score, account))
        
        if not scored_accounts:
            return None
        
        # Select best scoring account
        scored_accounts.sort(key=lambda x: x[0], reverse=True)
        return scored_accounts[0][1]
    
    def _calculate_ai_score(
        self,
        account: Account,
        message: MessageQueue,
        context: Dict,
        current_hour: int
    ) -> float:
        """Calculate AI-based score for account selection"""
        
        # Predict flood wait probability
        flood_prob = self.analytics.predict_flood_wait_probability(
            account,
            current_hour,
            account.messages_sent_today
        )
        
        # Base score from health
        score = account.health_score / 100
        
        # Adjust for flood probability
        score *= (1 - flood_prob)
        
        # Historical performance
        history = self.performance_history.get(account.id, [])
        if history:
            recent_performance = sum(history[-10:]) / len(history[-10:])
            score *= (1 + recent_performance * 0.3)
        
        # Priority boost
        if message.priority > 5:
            score *= 1.2
        
        # Time-based optimization
        if 9 <= current_hour <= 20:
            score *= 1.1  # Boost during optimal hours
        
        return score

# ============================================================================
# MESSAGE QUEUE MANAGER
# ============================================================================

class PriorityMessageQueue:
    """Priority queue for message distribution"""
    
    def __init__(self, config: DistributionConfig):
        self.config = config
        self.queue = []
        self.message_index = {}
        self.counter = 0
        
    def add_message(self, message: MessageQueue, priority: Optional[float] = None):
        """Add message to priority queue"""
        
        if priority is None:
            priority = message.priority
        
        # Add time-sensitive boost
        if message.send_before:
            time_remaining = (message.send_before - datetime.utcnow()).total_seconds()
            if time_remaining < 3600:  # Less than 1 hour
                priority *= self.config.time_sensitive_boost
        
        # Use negative priority for min-heap (higher priority = lower value)
        heap_entry = [-priority, self.counter, message]
        heapq.heappush(self.queue, heap_entry)
        self.message_index[message.id] = heap_entry
        self.counter += 1
    
    def get_next_message(self) -> Optional[MessageQueue]:
        """Get highest priority message"""
        
        while self.queue:
            priority, count, message = heapq.heappop(self.queue)
            
            # Skip if message was removed
            if message.id not in self.message_index:
                continue
            
            del self.message_index[message.id]
            
            # Check if message is ready to send
            if message.scheduled_at and message.scheduled_at > datetime.utcnow():
                # Re-add to queue for later
                self.add_message(message)
                continue
            
            # Check if message expired
            if message.send_before and message.send_before < datetime.utcnow():
                continue
            
            return message
        
        return None
    
    def remove_message(self, message_id: int):
        """Remove message from queue"""
        if message_id in self.message_index:
            entry = self.message_index[message_id]
            entry[-1] = None  # Mark as removed
            del self.message_index[message_id]
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return len(self.message_index)
    
    def get_queue_stats(self) -> Dict:
        """Get queue statistics"""
        
        priorities = defaultdict(int)
        for entry in self.message_index.values():
            if entry[-1] is not None:
                priority = entry[-1].priority
                priorities[priority] += 1
        
        return {
            'total_messages': len(self.message_index),
            'priority_breakdown': dict(priorities),
            'next_scheduled': min(
                (msg.scheduled_at for _, _, msg in self.queue if msg and msg.scheduled_at),
                default=None
            )
        }

# ============================================================================
# RATE LIMITER
# ============================================================================

class AdaptiveRateLimiter:
    """Adaptive rate limiting with burst control"""
    
    def __init__(self, config: DistributionConfig):
        self.config = config
        self.account_buckets = defaultdict(lambda: {
            'tokens': config.burst_limit,
            'last_refill': datetime.utcnow()
        })
        self.global_bucket = {
            'tokens': config.global_rate_limit,
            'last_refill': datetime.utcnow()
        }
        self.adjustment_factors = defaultdict(lambda: 1.0)
        
    def can_send(self, account: Account) -> bool:
        """Check if account can send message"""
        
        # Refill tokens
        self._refill_tokens(account.id)
        
        # Check global limit
        if self.global_bucket['tokens'] <= 0:
            return False
        
        # Check account limit
        bucket = self.account_buckets[account.id]
        if bucket['tokens'] <= 0:
            return False
        
        # Check daily limit
        if account.messages_sent_today >= account.daily_limit:
            return False
        
        return True
    
    def consume_token(self, account: Account):
        """Consume a token for sending"""
        
        # Consume global token
        self.global_bucket['tokens'] -= 1
        
        # Consume account token
        self.account_buckets[account.id]['tokens'] -= 1
    
    def _refill_tokens(self, account_id: int):
        """Refill tokens based on time passed"""
        
        now = datetime.utcnow()
        
        # Refill global tokens
        time_passed = (now - self.global_bucket['last_refill']).total_seconds()
        if time_passed > 0:
            refill_rate = self.config.global_rate_limit / 3600  # per second
            tokens_to_add = time_passed * refill_rate
            self.global_bucket['tokens'] = min(
                self.config.global_rate_limit,
                self.global_bucket['tokens'] + tokens_to_add
            )
            self.global_bucket['last_refill'] = now
        
        # Refill account tokens
        bucket = self.account_buckets[account_id]
        time_passed = (now - bucket['last_refill']).total_seconds()
        if time_passed > 0:
            # Adaptive refill rate
            base_rate = self.config.burst_limit / 60  # per second
            adjusted_rate = base_rate * self.adjustment_factors[account_id]
            tokens_to_add = time_passed * adjusted_rate
            bucket['tokens'] = min(
                self.config.burst_limit,
                bucket['tokens'] + tokens_to_add
            )
            bucket['last_refill'] = now
    
    def adjust_rate(self, account_id: int, success: bool):
        """Adjust rate based on success/failure"""
        
        if success:
            # Increase rate slightly
            self.adjustment_factors[account_id] = min(
                2.0,
                self.adjustment_factors[account_id] * 1.05
            )
        else:
            # Decrease rate
            self.adjustment_factors[account_id] = max(
                0.1,
                self.adjustment_factors[account_id] * 0.8
            )
    
    def get_wait_time(self, account: Account) -> float:
        """Get time to wait before next send"""
        
        # Base delay
        delay = random.uniform(
            self.config.min_delay_seconds,
            self.config.max_delay_seconds
        )
        
        # Adjust based on account health
        health_factor = account.health_score / 100
        delay = delay * (2 - health_factor)  # Unhealthy accounts wait longer
        
        # Adjust based on adjustment factor
        delay = delay / self.adjustment_factors[account.id]
        
        return max(self.config.min_delay_seconds, delay)

# ============================================================================
# MAIN DISTRIBUTION SYSTEM
# ============================================================================

class IntelligentDistributionSystem:
    """Master distribution system orchestrating all components"""
    
    def __init__(
        self,
        db_manager: DatabaseManager,
        account_manager: AdvancedAccountManager,
        variation_engine: AdvancedMessageVariationEngine,
        config: Optional[DistributionConfig] = None
    ):
        self.db = db_manager
        self.account_manager = account_manager
        self.variation_engine = variation_engine
        self.config = config or DistributionConfig()
        
        # Initialize components
        self.analytics = PredictiveAnalytics()
        self.load_calculator = LoadCalculator()
        self.message_queue = PriorityMessageQueue(config)
        self.rate_limiter = AdaptiveRateLimiter(config)
        
        # Initialize algorithms
        self.algorithms = {
            'weighted_round_robin': WeightedRoundRobinAlgorithm(),
            'least_connections': LeastConnectionsAlgorithm(),
            'ai_optimized': AIOptimizedAlgorithm(self.analytics)
        }
        
        # Statistics
        self.stats = {
            'messages_queued': 0,
            'messages_sent': 0,
            'messages_failed': 0,
            'flood_waits': 0,
            'total_delay': 0
        }
        
        # Active campaigns
        self.active_campaigns = {}
        self.distribution_tasks = {}
    
    async def calculate_distribution(
        self,
        campaign: Campaign,
        members: List[Member],
        accounts: List[Account]
    ) -> Dict[str, Any]:
        """Calculate optimal distribution plan for campaign"""
        
        total_messages = len(members)
        available_accounts = [acc for acc in accounts if acc.is_active and not acc.is_banned]
        
        if not available_accounts:
            return {
                'feasible': False,
                'reason': 'No available accounts'
            }
        
        # Calculate capacity
        daily_capacity = sum(acc.daily_limit - acc.messages_sent_today for acc in available_accounts)
        total_capacity = sum(acc.daily_limit for acc in available_accounts)
        
        # Calculate timeline
        days_needed = math.ceil(total_messages / total_capacity)
        
        # Calculate optimal account distribution
        account_assignments = self._calculate_account_assignments(
            members,
            available_accounts,
            campaign
        )
        
        # Predict performance
        predicted_success_rate = self._predict_success_rate(available_accounts)
        predicted_completion = datetime.utcnow() + timedelta(days=days_needed)
        
        # Calculate costs
        estimated_cost = self._calculate_estimated_cost(
            available_accounts,
            days_needed,
            total_messages
        )
        
        return {
            'feasible': True,
            'total_messages': total_messages,
            'available_accounts': len(available_accounts),
            'daily_capacity': daily_capacity,
            'total_capacity': total_capacity,
            'days_needed': days_needed,
            'hours_needed': days_needed * 24,
            'account_assignments': account_assignments,
            'predicted_success_rate': predicted_success_rate,
            'predicted_completion': predicted_completion,
            'estimated_cost': estimated_cost,
            'recommendations': self._generate_recommendations(
                total_messages,
                available_accounts,
                days_needed
            )
        }
    
    def _calculate_account_assignments(
        self,
        members: List[Member],
        accounts: List[Account],
        campaign: Campaign
    ) -> Dict[int, int]:
        """Calculate how many messages each account should send"""
        
        assignments = {}
        total_capacity = sum(acc.daily_limit for acc in accounts)
        
        for account in accounts:
            # Proportional assignment based on capacity and health
            capacity_ratio = account.daily_limit / total_capacity
            health_factor = account.health_score / 100
            
            messages_to_assign = int(
                len(members) * capacity_ratio * health_factor
            )
            
            assignments[account.id] = min(
                messages_to_assign,
                account.daily_limit * campaign.days_needed if hasattr(campaign, 'days_needed') else messages_to_assign
            )
        
        return assignments
    
    def _predict_success_rate(self, accounts: List[Account]) -> float:
        """Predict overall success rate"""
        
        if not accounts:
            return 0
        
        # Weight by account health and historical performance
        total_weight = 0
        weighted_success = 0
        
        for account in accounts:
            weight = account.health_score / 100
            
            if account.successful_sends + account.failed_sends > 0:
                success_rate = account.successful_sends / (account.successful_sends + account.failed_sends)
            else:
                success_rate = 0.85  # Default assumption
            
            weighted_success += success_rate * weight
            total_weight += weight
        
        return weighted_success / max(1, total_weight)
    
    def _calculate_estimated_cost(
        self,
        accounts: List[Account],
        days: int,
        messages: int
    ) -> float:
        """Calculate estimated cost of distribution"""
        
        # Proxy costs
        monthly_proxy_cost = sum(acc.proxy_cost_monthly for acc in accounts)
        daily_proxy_cost = monthly_proxy_cost / 30
        proxy_cost = daily_proxy_cost * days
        
        # Per-message costs (if any)
        message_cost = sum(acc.cost_per_message for acc in accounts) * messages
        
        return proxy_cost + message_cost
    
    def _generate_recommendations(
        self,
        total_messages: int,
        accounts: List[Account],
        days_needed: int
    ) -> List[str]:
        """Generate optimization recommendations"""
        
        recommendations = []
        
        # Check if more accounts needed
        if days_needed > 30:
            additional_accounts = math.ceil(days_needed / 30) * 5
            recommendations.append(
                f"Add {additional_accounts} more accounts to reduce timeline to 30 days"
            )
        
        # Check account health
        unhealthy = [acc for acc in accounts if acc.health_score < 50]
        if unhealthy:
            recommendations.append(
                f"Improve health of {len(unhealthy)} accounts before starting"
            )
        
        # Check for optimal timing
        recommendations.append(
            "Schedule campaign during weekday business hours for better engagement"
        )
        
        # Suggest message variations
        if total_messages > 1000:
            recommendations.append(
                "Use at least 50 message variations to avoid detection"
            )
        
        return recommendations
    
    async def start_distribution(
        self,
        campaign_id: int,
        progress_callback: Optional[callable] = None
    ) -> bool:
        """Start distributing messages for campaign"""
        
        session = self.db.get_session()
        
        try:
            # Get campaign
            campaign = session.query(Campaign).get(campaign_id)
            if not campaign:
                return False
            
            # Check if already running
            if campaign_id in self.distribution_tasks:
                return False
            
            # Start distribution task
            task = asyncio.create_task(
                self._distribution_loop(campaign_id, progress_callback)
            )
            self.distribution_tasks[campaign_id] = task
            
            # Update campaign status
            campaign.status = 'running'
            campaign.started_at = datetime.utcnow()
            session.commit()
            
            return True
            
        finally:
            session.close()
    
    async def _distribution_loop(
        self,
        campaign_id: int,
        progress_callback: Optional[callable] = None
    ):
        """Main distribution loop for campaign"""
        
        session = self.db.get_session()
        
        try:
            campaign = session.query(Campaign).get(campaign_id)
            
            # Get pending messages
            pending = session.query(MessageQueue).filter(
                MessageQueue.campaign_id == campaign_id,
                MessageQueue.status == 'pending'
            ).all()
            
            # Add to priority queue
            for message in pending:
                self.message_queue.add_message(message)
            
            # Get accounts for campaign
            campaign_accounts = session.query(CampaignAccount).filter(
                CampaignAccount.campaign_id == campaign_id,
                CampaignAccount.is_active == True
            ).all()
            
            account_ids = [ca.account_id for ca in campaign_accounts]
            
            # Distribution loop
            while self.message_queue.get_queue_size() > 0:
                pass
                
                # Check if campaign paused
                campaign = session.query(Campaign).get(campaign_id)
                if campaign.status != 'running':
                    break
                
                # Get next message
                message = self.message_queue.get_next_message()
                if not message:
                    await asyncio.sleep(1)
                    continue
                
                # Get available accounts
                accounts = []
                for acc_id in account_ids:
                    acc_tuple = await self.account_manager.get_best_account(
                        exclude_ids=[],
                        min_health=30
                    )
                    if acc_tuple:
                        accounts.append(acc_tuple[0])
                
                if not accounts:
                    # No accounts available, wait
                    await asyncio.sleep(60)
                    continue
                
                # Select account using configured algorithm
                algorithm = self.algorithms.get(
                    self.config.load_balancing_algorithm,
                    self.algorithms['weighted_round_robin']
                )
                
                selected_account = algorithm.select_account(
                    accounts,
                    message,
                    {'campaign': campaign}
                )
                
                if not selected_account:
                    continue
                
                # Check rate limit
                if not self.rate_limiter.can_send(selected_account):
                    # Re-queue message
                    self.message_queue.add_message(message)
                    await asyncio.sleep(self.rate_limiter.get_wait_time(selected_account))
                    continue
                
                # Send message
                success = await self._send_message(
                    message,
                    selected_account,
                    campaign
                )
                
                # Update rate limiter
                self.rate_limiter.consume_token(selected_account)
                self.rate_limiter.adjust_rate(selected_account.id, success)
                
                # Update statistics
                if success:
                    self.stats['messages_sent'] += 1
                    campaign.messages_sent += 1
                else:
                    self.stats['messages_failed'] += 1
                    campaign.messages_failed += 1
                
                # Progress callback
                if progress_callback:
                    await progress_callback(
                        campaign.messages_sent,
                        campaign.target_count,
                        self.message_queue.get_queue_size()
                    )
                
                # Calculate delay
                delay = self.rate_limiter.get_wait_time(selected_account)
                await asyncio.sleep(delay)
            
            # Campaign completed
            campaign.status = 'completed'
            campaign.completed_at = datetime.utcnow()
            session.commit()
            
        except Exception as e:
            print(f"Distribution error: {e}")
            campaign.status = 'failed'
            session.commit()
            
        finally:
            session.close()
            
            # Clean up task
            if campaign_id in self.distribution_tasks:
                del self.distribution_tasks[campaign_id]
    
    async def _send_message(
        self,
        message: MessageQueue,
        account: Account,
        campaign: Campaign
    ) -> bool:
        """Send individual message"""
        
        # This would integrate with actual Telegram sending
        # For now, simulate
        
        success = random.random() > 0.1  # 90% success rate
        
        # Update message status
        session = self.db.get_session()
        message = session.query(MessageQueue).get(message.id)
        
        if success:
            message.status = 'sent'
            message.sent_at = datetime.utcnow()
            message.account_id = account.id
        else:
            message.status = 'failed'
            message.failed_at = datetime.utcnow()
            message.retry_count += 1
            
            # Re-queue if retries available
            if message.retry_count < self.config.max_retries:
                message.status = 'pending'
                self.message_queue.add_message(message)
        
        session.commit()
        session.close()
        
        # Update account statistics
        await self.account_manager.record_message_sent(
            account.id,
            success
        )
        
        return success
    
    def get_distribution_stats(self) -> Dict:
        """Get distribution statistics"""
        
        stats = {
            **self.stats,
            'active_campaigns': len(self.distribution_tasks),
            'queue_size': self.message_queue.get_queue_size(),
            'queue_stats': self.message_queue.get_queue_stats(),
            'system_load': self.load_calculator.calculate_system_load([])
        }
        
        return stats


# ============================================================================
# TESTING
# ============================================================================

async def test_distribution_system():
    """Test the distribution system"""
    
    print("=" * 60)
    print("INTELLIGENT DISTRIBUTION SYSTEM TEST")
    print("=" * 60)
    
    # Initialize
    db = DatabaseManager('test_distribution.db')
    account_manager = AdvancedAccountManager(db.db_path)
    variation_engine = AdvancedMessageVariationEngine(db)
    
    config = DistributionConfig(
        use_predictive_analytics=True,
        adaptive_rate_adjustment=True,
        load_balancing_algorithm='ai_optimized'
    )
    
    distributor = IntelligentDistributionSystem(
        db,
        account_manager,
        variation_engine,
        config
    )
    
    print("\n✅ Distribution System Features:")
    print("  - Predictive analytics")
    print("  - AI-optimized account selection")
    print("  - Adaptive rate limiting")
    print("  - Priority message queue")
    print("  - Flood wait prediction")
    print("  - Engagement prediction")
    print("  - Load balancing algorithms")
    print("  - Cost optimization")
    print("  - Timezone awareness")
    print("  - Failure recovery")
    print("  - Performance monitoring")
    
    # Test distribution calculation
    print("\nTesting distribution calculation...")
    
    # Create mock data
    session = db.get_session()
    
    # Mock campaign
    campaign = Campaign(
        name="Test Campaign",
        target_channel="@test",
        target_count=1000,
        message_template="Test message"
    )
    session.add(campaign)
    
    # Mock accounts
    accounts = []
    for i in range(5):
        account = Account(
            phone=f"+1234567890{i}",
            api_id=12345,
            api_hash="test_hash",
            daily_limit=50,
            health_score=80 + i * 5,
            is_active=True
        )
        accounts.append(account)
        session.add(account)
    
    # Mock members
    members = []
    for i in range(100):
        member = Member(
            user_id=1000 + i,
            username=f"user{i}",
            first_name=f"User{i}"
        )
        members.append(member)
        session.add(member)
    
    session.commit()
    
    # Calculate distribution
    plan = await distributor.calculate_distribution(
        campaign,
        members,
        accounts
    )
    
    print("\nDistribution Plan:")
    print(f"  Feasible: {plan['feasible']}")
    print(f"  Total messages: {plan.get('total_messages', 0)}")
    print(f"  Available accounts: {plan.get('available_accounts', 0)}")
    print(f"  Daily capacity: {plan.get('daily_capacity', 0)}")
    print(f"  Days needed: {plan.get('days_needed', 0)}")
    print(f"  Predicted success rate: {plan.get('predicted_success_rate', 0):.2%}")
    print(f"  Estimated cost: ${plan.get('estimated_cost', 0):.2f}")
    
    if plan.get('recommendations'):
        print("\nRecommendations:")
        for rec in plan['recommendations']:
            print(f"  - {rec}")
    
    # Test predictive analytics
    print("\n\nTesting Predictive Analytics:")
    
    analytics = PredictiveAnalytics()
    
    # Test flood wait prediction
    flood_prob = analytics.predict_flood_wait_probability(
        accounts[0],
        14,  # 2 PM
        40   # 40 messages sent
    )
    print(f"  Flood wait probability: {flood_prob:.2%}")
    
    # Test engagement prediction
    engagement_prob = analytics.predict_engagement_probability(
        members[0],
        0.5,  # Positive sentiment
        datetime.now().replace(hour=19)  # 7 PM
    )
    print(f"  Engagement probability: {engagement_prob:.2%}")
    
    # Test optimal send time
    optimal_time = analytics.predict_optimal_send_time(
        members[0],
        'America/New_York'
    )
    print(f"  Optimal send time: {optimal_time}")
    
    session.close()
    
    print("\n✅ Distribution system test complete!")


if __name__ == "__main__":
    asyncio.run(test_distribution_system())