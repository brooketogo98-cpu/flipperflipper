#!/usr/bin/env python3
"""
Telegram Automation System - Complete Database Layer
NO SHORTCUTS - Full implementation with all features
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean, 
    Float, DateTime, ForeignKey, Index, JSON, DECIMAL, 
    UniqueConstraint, CheckConstraint, event, case
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session, backref
from sqlalchemy.pool import QueuePool
from sqlalchemy.sql import func
from sqlalchemy.ext.hybrid import hybrid_property
import sqlalchemy.exc

Base = declarative_base()

# ============================================================================
# COMPLETE DATABASE MODELS - NO SHORTCUTS
# ============================================================================

class Member(Base):
    """Complete member model with all fields and relationships"""
    __tablename__ = 'members'
    
    # Primary fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, unique=True, nullable=False, index=True)
    username = Column(String(255), index=True)
    first_name = Column(String(255))
    last_name = Column(String(255))
    phone = Column(String(50))
    bio = Column(Text)
    
    # Status flags
    is_bot = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    is_restricted = Column(Boolean, default=False)
    is_scam = Column(Boolean, default=False)
    is_fake = Column(Boolean, default=False)
    is_premium = Column(Boolean, default=False)
    
    # Activity tracking
    status = Column(String(50))  # online, offline, recently, long_time_ago
    last_seen = Column(DateTime)
    last_active = Column(DateTime)
    
    # Telegram specific
    access_hash = Column(String(255))
    photo_id = Column(String(255))
    photo_url = Column(String(500))
    language_code = Column(String(10))
    
    # Scraping metadata
    scraped_from = Column(String(255), index=True)
    scraped_at = Column(DateTime, default=datetime.utcnow, index=True)
    scrape_method = Column(String(50))  # standard, messages, reactions, forwards, related
    source_message_id = Column(Integer)  # If scraped from message
    
    # Contact tracking
    contacted_at = Column(DateTime, index=True)
    contact_attempts = Column(Integer, default=0)
    contact_success = Column(Boolean, default=False)
    last_contact_status = Column(String(100))
    
    # Response tracking
    response_received = Column(Boolean, default=False)
    response_time = Column(DateTime)
    response_sentiment = Column(String(50))  # positive, negative, neutral
    response_text = Column(Text)
    
    # Engagement metrics
    engagement_score = Column(Float, default=0.0)
    interaction_count = Column(Integer, default=0)
    click_through = Column(Boolean, default=False)
    conversion = Column(Boolean, default=False)
    
    # Custom fields
    tags = Column(JSON)  # Custom tags for categorization
    custom_fields = Column(JSON)  # Flexible additional data
    notes = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    messages = relationship("MessageQueue", back_populates="member", cascade="all, delete-orphan")
    campaign_members = relationship("CampaignMember", back_populates="member", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_user_status', 'status', 'contacted_at'),
        Index('idx_engagement', 'engagement_score', 'response_received'),
        Index('idx_scrape_info', 'scraped_from', 'scrape_method', 'scraped_at'),
    )
    
    @hybrid_property
    def full_name(self):
        """Get full name"""
        parts = [self.first_name, self.last_name]
        return ' '.join(filter(None, parts)) or self.username or f"User{self.user_id}"
    
    @hybrid_property
    def days_since_contact(self):
        """Calculate days since last contact"""
        if not self.contacted_at:
            return None
        return (datetime.utcnow() - self.contacted_at).days
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'full_name': self.full_name,
            'phone': self.phone,
            'bio': self.bio,
            'status': self.status,
            'is_bot': self.is_bot,
            'is_verified': self.is_verified,
            'scraped_from': self.scraped_from,
            'scraped_at': self.scraped_at.isoformat() if self.scraped_at else None,
            'contacted_at': self.contacted_at.isoformat() if self.contacted_at else None,
            'engagement_score': self.engagement_score,
            'response_received': self.response_received,
        }


class Account(Base):
    """Complete account model with health tracking and management"""
    __tablename__ = 'accounts'
    
    # Primary fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    phone = Column(String(50), unique=True, nullable=False, index=True)
    api_id = Column(Integer, nullable=False)
    api_hash = Column(String(255), nullable=False)
    
    # Session management
    session_file = Column(String(255), nullable=False)
    session_string = Column(Text)  # For string sessions
    session_encrypted = Column(Boolean, default=True)
    encryption_key = Column(String(255))
    
    # Proxy configuration
    proxy_type = Column(String(20))  # http, socks5, mtproto
    proxy_host = Column(String(255))
    proxy_port = Column(Integer)
    proxy_username = Column(String(255))
    proxy_password = Column(String(255))
    proxy_secret = Column(String(255))  # For MTProto
    
    # Account information
    user_id = Column(Integer)
    username = Column(String(255))
    first_name = Column(String(255))
    last_name = Column(String(255))
    bio = Column(Text)
    profile_photo = Column(String(500))
    
    # Status tracking
    is_active = Column(Boolean, default=True, index=True)
    is_banned = Column(Boolean, default=False)
    is_limited = Column(Boolean, default=False)
    is_flood_waited = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    is_premium = Column(Boolean, default=False)
    
    # Limitation tracking
    ban_reason = Column(Text)
    ban_date = Column(DateTime)
    limitation_reason = Column(String(255))
    limitation_expires = Column(DateTime)
    flood_wait_until = Column(DateTime)
    
    # Usage statistics
    messages_sent_today = Column(Integer, default=0)
    messages_sent_week = Column(Integer, default=0)
    messages_sent_month = Column(Integer, default=0)
    messages_sent_total = Column(Integer, default=0)
    
    # Flood tracking
    flood_waits_today = Column(Integer, default=0)
    flood_waits_week = Column(Integer, default=0)
    flood_waits_total = Column(Integer, default=0)
    last_flood_wait = Column(DateTime)
    avg_flood_wait_seconds = Column(Float, default=0.0)
    
    # Success metrics
    successful_sends = Column(Integer, default=0)
    failed_sends = Column(Integer, default=0)
    delivery_rate = Column(Float, default=0.0)
    response_rate = Column(Float, default=0.0)
    
    # Health and reputation
    health_score = Column(Integer, default=100, index=True)
    reputation_score = Column(Integer, default=100)
    trust_score = Column(Integer, default=50)
    ban_risk_score = Column(Integer, default=0)
    
    # Rate limits
    daily_limit = Column(Integer, default=50)
    hourly_limit = Column(Integer, default=10)
    burst_limit = Column(Integer, default=5)
    min_delay_seconds = Column(Float, default=3.0)
    max_delay_seconds = Column(Float, default=10.0)
    
    # Account age and warmup
    created_at = Column(DateTime, default=datetime.utcnow)
    warmed_up = Column(Boolean, default=False)
    warmup_completed_at = Column(DateTime)
    account_age_days = Column(Integer, default=0)
    
    # Usage tracking
    last_used = Column(DateTime, index=True)
    last_message_at = Column(DateTime)
    last_login = Column(DateTime)
    total_online_hours = Column(Float, default=0.0)
    
    # Cost tracking
    cost_per_message = Column(DECIMAL(10, 4), default=0.0)
    total_cost = Column(DECIMAL(10, 2), default=0.0)
    proxy_cost_monthly = Column(DECIMAL(10, 2), default=0.0)
    
    # Configuration
    configuration = Column(JSON)  # Flexible config storage
    notes = Column(Text)
    tags = Column(JSON)
    
    # Timestamps
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    messages = relationship("MessageQueue", back_populates="account", cascade="all, delete-orphan")
    health_logs = relationship("AccountHealthLog", back_populates="account", cascade="all, delete-orphan")
    campaign_accounts = relationship("CampaignAccount", back_populates="account", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_account_health', 'health_score', 'is_active'),
        Index('idx_account_usage', 'last_used', 'messages_sent_today'),
        CheckConstraint('health_score >= 0 AND health_score <= 100'),
        CheckConstraint('reputation_score >= 0 AND reputation_score <= 100'),
    )
    
    @hybrid_property
    def is_available(self):
        """Check if account is available for use"""
        if not self.is_active or self.is_banned:
            return False
        if self.is_flood_waited and self.flood_wait_until:
            return datetime.utcnow() > self.flood_wait_until
        return True
    
    @hybrid_property
    def capacity_remaining_today(self):
        """Calculate remaining message capacity for today"""
        return max(0, self.daily_limit - self.messages_sent_today)
    
    @hybrid_property
    def success_rate(self):
        """Calculate success rate"""
        total = self.successful_sends + self.failed_sends
        if total == 0:
            return 0.0
        return (self.successful_sends / total) * 100
    
    def calculate_health_score(self):
        """Recalculate health score based on multiple factors"""
        score = 100
        
        # Deduct for bans and limitations
        if self.is_banned:
            return 0
        if self.is_limited:
            score -= 30
        if self.is_flood_waited:
            score -= 20
            
        # Deduct for flood waits
        score -= min(30, self.flood_waits_today * 5)
        
        # Deduct for failed sends
        if self.failed_sends > 0:
            fail_rate = self.failed_sends / max(1, self.successful_sends + self.failed_sends)
            score -= int(fail_rate * 30)
            
        # Bonus for good performance
        if self.success_rate > 95:
            score += 10
        elif self.success_rate > 90:
            score += 5
            
        # Account age bonus
        if self.account_age_days > 90:
            score += 10
        elif self.account_age_days > 30:
            score += 5
            
        return max(0, min(100, score))
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'phone': self.phone,
            'username': self.username,
            'first_name': self.first_name,
            'is_active': self.is_active,
            'health_score': self.health_score,
            'reputation_score': self.reputation_score,
            'messages_sent_today': self.messages_sent_today,
            'capacity_remaining': self.capacity_remaining_today,
            'success_rate': self.success_rate,
            'is_available': self.is_available,
            'last_used': self.last_used.isoformat() if self.last_used else None,
        }


class Campaign(Base):
    """Complete campaign model with full tracking and analytics"""
    __tablename__ = 'campaigns'
    
    # Primary fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    campaign_type = Column(String(50), default='mass_dm')  # mass_dm, targeted, follow_up, etc.
    
    # Target configuration
    target_channel = Column(String(255))
    target_channels = Column(JSON)  # Multiple channels
    target_filters = Column(JSON)  # Filtering criteria
    target_count = Column(Integer)
    
    # Message configuration
    message_template = Column(Text, nullable=False)
    message_variations = Column(JSON)  # Pre-generated variations
    variations_count = Column(Integer, default=10)
    personalization_enabled = Column(Boolean, default=True)
    
    # Timing configuration
    schedule_type = Column(String(50), default='immediate')  # immediate, scheduled, recurring
    scheduled_start = Column(DateTime)
    scheduled_end = Column(DateTime)
    time_zone = Column(String(50), default='UTC')
    active_hours_start = Column(Integer, default=9)  # 9 AM
    active_hours_end = Column(Integer, default=21)  # 9 PM
    active_days = Column(JSON)  # ['monday', 'tuesday', ...]
    
    # Rate limiting
    messages_per_day_limit = Column(Integer, default=1000)
    messages_per_hour_limit = Column(Integer, default=100)
    messages_per_account_limit = Column(Integer, default=50)
    min_delay_between_messages = Column(Float, default=5.0)
    max_delay_between_messages = Column(Float, default=15.0)
    
    # Status tracking
    status = Column(String(50), default='draft', index=True)  # draft, ready, running, paused, completed, failed
    approval_status = Column(String(50), default='pending')  # pending, approved, rejected
    approved_by = Column(String(255))
    approved_at = Column(DateTime)
    
    # Progress tracking
    messages_queued = Column(Integer, default=0)
    messages_sent = Column(Integer, default=0)
    messages_delivered = Column(Integer, default=0)
    messages_read = Column(Integer, default=0)
    messages_failed = Column(Integer, default=0)
    messages_remaining = Column(Integer, default=0)
    
    # Response tracking
    responses_received = Column(Integer, default=0)
    positive_responses = Column(Integer, default=0)
    negative_responses = Column(Integer, default=0)
    neutral_responses = Column(Integer, default=0)
    
    # Performance metrics
    success_rate = Column(Float, default=0.0)
    delivery_rate = Column(Float, default=0.0)
    read_rate = Column(Float, default=0.0)
    response_rate = Column(Float, default=0.0)
    click_through_rate = Column(Float, default=0.0)
    conversion_rate = Column(Float, default=0.0)
    
    # Account usage
    accounts_used = Column(Integer, default=0)
    accounts_banned = Column(Integer, default=0)
    accounts_limited = Column(Integer, default=0)
    
    # Time tracking
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime)
    paused_at = Column(DateTime)
    resumed_at = Column(DateTime)
    completed_at = Column(DateTime)
    failed_at = Column(DateTime)
    
    # Duration and estimates
    estimated_duration_hours = Column(Float)
    actual_duration_hours = Column(Float)
    estimated_cost = Column(DECIMAL(10, 2))
    actual_cost = Column(DECIMAL(10, 2))
    
    # Error tracking
    error_count = Column(Integer, default=0)
    last_error = Column(Text)
    last_error_at = Column(DateTime)
    
    # Configuration
    configuration = Column(JSON)  # Complete campaign config
    analytics = Column(JSON)  # Real-time analytics data
    extra_data = Column(JSON)  # Additional metadata (renamed from 'metadata' which is reserved)
    
    # A/B testing
    is_ab_test = Column(Boolean, default=False)
    ab_test_variants = Column(JSON)
    winning_variant = Column(String(50))
    
    # Compliance
    compliance_checked = Column(Boolean, default=False)
    opt_out_honored = Column(Boolean, default=True)
    consent_required = Column(Boolean, default=True)
    
    # Timestamps
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    messages = relationship("MessageQueue", back_populates="campaign", cascade="all, delete-orphan")
    campaign_members = relationship("CampaignMember", back_populates="campaign", cascade="all, delete-orphan")
    campaign_accounts = relationship("CampaignAccount", back_populates="campaign", cascade="all, delete-orphan")
    campaign_logs = relationship("CampaignLog", back_populates="campaign", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_campaign_status', 'status', 'created_at'),
        Index('idx_campaign_performance', 'success_rate', 'response_rate'),
    )
    
    @hybrid_property
    def progress_percentage(self):
        """Calculate campaign progress"""
        if not self.target_count or self.target_count == 0:
            return 0.0
        return (self.messages_sent / self.target_count) * 100
    
    @hybrid_property
    def estimated_completion(self):
        """Estimate completion time"""
        if not self.started_at or self.messages_sent == 0:
            return None
        
        elapsed = datetime.utcnow() - self.started_at
        rate = self.messages_sent / max(1, elapsed.total_seconds() / 3600)  # msgs per hour
        
        if rate == 0:
            return None
            
        remaining = self.messages_remaining
        hours_needed = remaining / rate
        
        return datetime.utcnow() + timedelta(hours=hours_needed)
    
    def calculate_metrics(self):
        """Recalculate all campaign metrics"""
        total_sent = max(1, self.messages_sent)
        
        self.delivery_rate = (self.messages_delivered / total_sent) * 100
        self.read_rate = (self.messages_read / max(1, self.messages_delivered)) * 100
        self.response_rate = (self.responses_received / total_sent) * 100
        self.success_rate = ((total_sent - self.messages_failed) / total_sent) * 100
        
        if self.started_at:
            elapsed = datetime.utcnow() - self.started_at
            self.actual_duration_hours = elapsed.total_seconds() / 3600
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'target_count': self.target_count,
            'messages_sent': self.messages_sent,
            'messages_remaining': self.messages_remaining,
            'progress_percentage': self.progress_percentage,
            'success_rate': self.success_rate,
            'response_rate': self.response_rate,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'estimated_completion': self.estimated_completion.isoformat() if self.estimated_completion else None,
            'configuration': self.configuration,
        }


class MessageQueue(Base):
    """Complete message queue with retry logic and tracking"""
    __tablename__ = 'message_queue'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Relationships
    campaign_id = Column(Integer, ForeignKey('campaigns.id'), nullable=False, index=True)
    member_id = Column(Integer, ForeignKey('members.id'), nullable=False, index=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), index=True)
    variation_id = Column(Integer, ForeignKey('message_variations.id'))
    
    # Message content
    message_text = Column(Text, nullable=False)
    message_type = Column(String(50), default='text')  # text, photo, document, etc.
    media_path = Column(String(500))
    media_caption = Column(Text)
    
    # Priority and scheduling
    priority = Column(Integer, default=5, index=True)  # 1-10, higher = more important
    scheduled_at = Column(DateTime, index=True)
    send_after = Column(DateTime)  # Don't send before this time
    send_before = Column(DateTime)  # Must send before this time
    
    # Status tracking
    status = Column(String(50), default='pending', index=True)
    # pending, scheduled, sending, sent, delivered, read, failed, cancelled, expired
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    queued_at = Column(DateTime)
    sent_at = Column(DateTime)
    delivered_at = Column(DateTime)
    read_at = Column(DateTime)
    failed_at = Column(DateTime)
    
    # Error handling
    failure_reason = Column(Text)
    error_code = Column(String(100))
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    retry_after = Column(DateTime)
    
    # Tracking
    message_id = Column(String(255))  # Telegram message ID
    chat_id = Column(Integer)  # Telegram chat ID
    delivery_receipt = Column(JSON)
    read_receipt = Column(JSON)
    
    # Response tracking
    response_received = Column(Boolean, default=False)
    response_text = Column(Text)
    response_time = Column(DateTime)
    
    # Performance
    processing_time_ms = Column(Integer)
    api_response_time_ms = Column(Integer)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="messages")
    member = relationship("Member", back_populates="messages")
    account = relationship("Account", back_populates="messages")
    variation = relationship("MessageVariation")
    
    # Indexes
    __table_args__ = (
        Index('idx_queue_status_priority', 'status', 'priority', 'scheduled_at'),
        Index('idx_queue_campaign_status', 'campaign_id', 'status'),
        Index('idx_queue_retry', 'retry_count', 'retry_after'),
    )
    
    @hybrid_property
    def can_retry(self):
        """Check if message can be retried"""
        return (self.retry_count < self.max_retries and 
                self.status == 'failed' and
                (not self.retry_after or datetime.utcnow() > self.retry_after))
    
    @hybrid_property
    def is_expired(self):
        """Check if message has expired"""
        if self.send_before:
            return datetime.utcnow() > self.send_before
        return False


class MessageVariation(Base):
    """Store and track message variations"""
    __tablename__ = 'message_variations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(Integer, ForeignKey('campaigns.id'), nullable=False, index=True)
    
    # Variation content
    original_text = Column(Text, nullable=False)
    variation_text = Column(Text, nullable=False)
    variation_method = Column(String(50))  # gpt4, synonyms, structure, etc.
    
    # Quality scores
    uniqueness_score = Column(Float, default=0.0)
    quality_score = Column(Float, default=0.0)
    spam_score = Column(Float, default=0.0)
    similarity_score = Column(Float, default=0.0)
    
    # Usage tracking
    times_used = Column(Integer, default=0)
    successful_sends = Column(Integer, default=0)
    failed_sends = Column(Integer, default=0)
    responses_received = Column(Integer, default=0)
    
    # Performance
    delivery_rate = Column(Float, default=0.0)
    response_rate = Column(Float, default=0.0)
    engagement_score = Column(Float, default=0.0)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100), default='system')
    
    # A/B testing
    variant_group = Column(String(50))
    is_control = Column(Boolean, default=False)
    
    __table_args__ = (
        Index('idx_variation_scores', 'uniqueness_score', 'quality_score'),
        Index('idx_variation_performance', 'delivery_rate', 'response_rate'),
    )


class AccountHealthLog(Base):
    """Track account health over time"""
    __tablename__ = 'account_health_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False, index=True)
    
    # Health metrics
    health_score = Column(Integer, nullable=False)
    reputation_score = Column(Integer)
    trust_score = Column(Integer)
    ban_risk_score = Column(Integer)
    
    # Usage metrics
    messages_sent = Column(Integer)
    flood_waits = Column(Integer)
    failures = Column(Integer)
    
    # Event tracking
    event_type = Column(String(50))  # flood_wait, ban, limitation, recovery, etc.
    event_description = Column(Text)
    event_severity = Column(String(20))  # info, warning, error, critical
    
    # Timestamp
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationship
    account = relationship("Account", back_populates="health_logs")
    
    __table_args__ = (
        Index('idx_health_log_time', 'account_id', 'recorded_at'),
    )


class CampaignMember(Base):
    """Many-to-many relationship between campaigns and members"""
    __tablename__ = 'campaign_members'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(Integer, ForeignKey('campaigns.id'), nullable=False)
    member_id = Column(Integer, ForeignKey('members.id'), nullable=False)
    
    # Status
    included = Column(Boolean, default=True)
    excluded_reason = Column(String(255))
    
    # Tracking
    added_at = Column(DateTime, default=datetime.utcnow)
    contacted_at = Column(DateTime)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="campaign_members")
    member = relationship("Member", back_populates="campaign_members")
    
    __table_args__ = (
        UniqueConstraint('campaign_id', 'member_id'),
        Index('idx_campaign_member', 'campaign_id', 'member_id'),
    )


class CampaignAccount(Base):
    """Track which accounts are used for which campaigns"""
    __tablename__ = 'campaign_accounts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(Integer, ForeignKey('campaigns.id'), nullable=False)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False)
    
    # Usage tracking
    messages_sent = Column(Integer, default=0)
    messages_failed = Column(Integer, default=0)
    flood_waits = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    deactivated_reason = Column(String(255))
    
    # Timestamps
    assigned_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="campaign_accounts")
    account = relationship("Account", back_populates="campaign_accounts")
    
    __table_args__ = (
        UniqueConstraint('campaign_id', 'account_id'),
        Index('idx_campaign_account', 'campaign_id', 'account_id', 'is_active'),
    )


class CampaignLog(Base):
    """Detailed logging for campaign events"""
    __tablename__ = 'campaign_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(Integer, ForeignKey('campaigns.id'), nullable=False, index=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # started, paused, resumed, completed, error, etc.
    event_description = Column(Text)
    event_data = Column(JSON)
    severity = Column(String(20), default='info')  # info, warning, error, critical
    
    # Context
    account_id = Column(Integer, ForeignKey('accounts.id'))
    member_id = Column(Integer, ForeignKey('members.id'))
    message_id = Column(Integer, ForeignKey('message_queue.id'))
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="campaign_logs")
    
    __table_args__ = (
        Index('idx_campaign_log_type', 'campaign_id', 'event_type', 'created_at'),
    )


class ScrapingSession(Base):
    """Track scraping operations"""
    __tablename__ = 'scraping_sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Target information
    target_channel = Column(String(255), nullable=False)
    target_type = Column(String(50))  # channel, group, supergroup
    target_title = Column(String(255))
    target_member_count = Column(Integer)
    
    # Scraping configuration
    scrape_methods = Column(JSON)  # ['standard', 'messages', 'reactions', etc.]
    include_admins = Column(Boolean, default=True)
    include_bots = Column(Boolean, default=False)
    message_limit = Column(Integer, default=1000)
    
    # Results
    members_found = Column(Integer, default=0)
    new_members = Column(Integer, default=0)
    duplicate_members = Column(Integer, default=0)
    
    # Method breakdown
    standard_method_count = Column(Integer, default=0)
    message_method_count = Column(Integer, default=0)
    reaction_method_count = Column(Integer, default=0)
    forward_method_count = Column(Integer, default=0)
    related_method_count = Column(Integer, default=0)
    
    # Performance
    duration_seconds = Column(Float)
    errors_encountered = Column(Integer, default=0)
    
    # Status
    status = Column(String(50), default='running')  # running, completed, failed
    error_message = Column(Text)
    
    # Timestamps
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Account used
    account_id = Column(Integer, ForeignKey('accounts.id'))
    
    __table_args__ = (
        Index('idx_scraping_target', 'target_channel', 'started_at'),
    )


# ============================================================================
# DATABASE MANAGER - COMPLETE IMPLEMENTATION
# ============================================================================

class DatabaseManager:
    """Complete database management with all operations"""
    
    def __init__(self, db_path='telegram_automation.db', echo=False):
        """Initialize database with connection pooling and optimization"""
        self.db_path = db_path
        self.engine = create_engine(
            f'sqlite:///{db_path}',
            echo=echo,
            poolclass=QueuePool,
            pool_size=20,
            max_overflow=40,
            pool_timeout=30,
            pool_recycle=3600,
            connect_args={
                'check_same_thread': False,
                'timeout': 30
            }
        )
        
        # Enable SQLite optimizations
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
            cursor.execute("PRAGMA synchronous=NORMAL")  # Faster writes
            cursor.execute("PRAGMA cache_size=10000")  # Larger cache
            cursor.execute("PRAGMA temp_store=MEMORY")  # Use memory for temp tables
            cursor.execute("PRAGMA mmap_size=30000000000")  # Memory-mapped I/O
            cursor.close()
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Session factory
        self.SessionFactory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(self.SessionFactory)
    
    def get_session(self):
        """Get a new database session"""
        return self.Session()
    
    def close_session(self, session):
        """Close a database session"""
        session.close()
    
    # ========== Member Operations ==========
    
    def add_member(self, session, member_data):
        """Add a new member with deduplication"""
        existing = session.query(Member).filter_by(user_id=member_data['user_id']).first()
        if existing:
            # Update existing member
            for key, value in member_data.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.utcnow()
            return existing
        else:
            # Create new member
            member = Member(**member_data)
            session.add(member)
            return member
    
    def bulk_add_members(self, session, members_data):
        """Bulk add members with deduplication"""
        added = 0
        updated = 0
        
        for member_data in members_data:
            existing = session.query(Member).filter_by(user_id=member_data['user_id']).first()
            if existing:
                for key, value in member_data.items():
                    setattr(existing, key, value)
                existing.updated_at = datetime.utcnow()
                updated += 1
            else:
                member = Member(**member_data)
                session.add(member)
                added += 1
        
        session.commit()
        return {'added': added, 'updated': updated}
    
    def get_uncontacted_members(self, session, limit=None):
        """Get members who haven't been contacted"""
        query = session.query(Member).filter(
            Member.contacted_at.is_(None),
            Member.is_bot == False
        )
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def mark_member_contacted(self, session, member_id, success=True):
        """Mark a member as contacted"""
        member = session.query(Member).get(member_id)
        if member:
            member.contacted_at = datetime.utcnow()
            member.contact_attempts += 1
            member.contact_success = success
            session.commit()
    
    # ========== Account Operations ==========
    
    def add_account(self, session, account_data):
        """Add a new account"""
        account = Account(**account_data)
        session.add(account)
        session.commit()
        return account
    
    def get_available_accounts(self, session):
        """Get all available accounts sorted by health"""
        return session.query(Account).filter(
            Account.is_active == True,
            Account.is_banned == False
        ).order_by(Account.health_score.desc()).all()
    
    def get_best_account(self, session, exclude_ids=None):
        """Get the best available account"""
        query = session.query(Account).filter(
            Account.is_active == True,
            Account.is_banned == False,
            Account.health_score > 50
        )
        
        if exclude_ids:
            query = query.filter(~Account.id.in_(exclude_ids))
        
        # Complex scoring query
        accounts = query.all()
        if not accounts:
            return None
        
        best_account = None
        best_score = -1
        
        for account in accounts:
            # Calculate composite score
            score = (
                account.health_score * 2 +
                account.reputation_score * 1.5 +
                (100 - min(100, account.messages_sent_today * 2)) * 3 +
                (100 - min(100, account.flood_waits_today * 10)) * 2
            )
            
            if score > best_score:
                best_score = score
                best_account = account
        
        return best_account
    
    def update_account_health(self, session, account_id, health_delta=0, event=None):
        """Update account health score"""
        account = session.query(Account).get(account_id)
        if account:
            old_health = account.health_score
            account.health_score = max(0, min(100, account.health_score + health_delta))
            
            # Log health change
            if event:
                log = AccountHealthLog(
                    account_id=account_id,
                    health_score=account.health_score,
                    reputation_score=account.reputation_score,
                    event_type=event['type'],
                    event_description=event.get('description'),
                    event_severity=event.get('severity', 'info')
                )
                session.add(log)
            
            session.commit()
            return account.health_score
        return None
    
    def record_message_sent(self, session, account_id, success=True):
        """Record that an account sent a message"""
        account = session.query(Account).get(account_id)
        if account:
            account.messages_sent_today += 1
            account.messages_sent_total += 1
            account.last_message_at = datetime.utcnow()
            account.last_used = datetime.utcnow()
            
            if success:
                account.successful_sends += 1
            else:
                account.failed_sends += 1
            
            # Recalculate rates
            account.delivery_rate = account.success_rate
            
            session.commit()
    
    def record_flood_wait(self, session, account_id, wait_seconds):
        """Record a flood wait event"""
        account = session.query(Account).get(account_id)
        if account:
            account.flood_waits_today += 1
            account.flood_waits_total += 1
            account.last_flood_wait = datetime.utcnow()
            account.flood_wait_until = datetime.utcnow() + timedelta(seconds=wait_seconds)
            account.is_flood_waited = True
            
            # Update average
            if account.avg_flood_wait_seconds == 0:
                account.avg_flood_wait_seconds = wait_seconds
            else:
                account.avg_flood_wait_seconds = (account.avg_flood_wait_seconds + wait_seconds) / 2
            
            # Decrease health
            self.update_account_health(session, account_id, -10, {
                'type': 'flood_wait',
                'description': f'Flood wait for {wait_seconds} seconds',
                'severity': 'warning'
            })
            
            session.commit()
    
    def reset_daily_limits(self, session):
        """Reset daily limits for all accounts"""
        accounts = session.query(Account).all()
        for account in accounts:
            account.messages_sent_today = 0
            account.flood_waits_today = 0
            
            # Clear flood wait if expired
            if account.flood_wait_until and datetime.utcnow() > account.flood_wait_until:
                account.is_flood_waited = False
                account.flood_wait_until = None
        
        session.commit()
    
    # ========== Campaign Operations ==========
    
    def create_campaign(self, session, campaign_data):
        """Create a new campaign"""
        campaign = Campaign(**campaign_data)
        session.add(campaign)
        session.commit()
        return campaign
    
    def get_active_campaigns(self, session):
        """Get all active campaigns"""
        return session.query(Campaign).filter(
            Campaign.status.in_(['running', 'scheduled'])
        ).all()
    
    def start_campaign(self, session, campaign_id):
        """Start a campaign"""
        campaign = session.query(Campaign).get(campaign_id)
        if campaign:
            campaign.status = 'running'
            campaign.started_at = datetime.utcnow()
            
            # Log event
            log = CampaignLog(
                campaign_id=campaign_id,
                event_type='started',
                event_description='Campaign started'
            )
            session.add(log)
            session.commit()
            return True
        return False
    
    def pause_campaign(self, session, campaign_id, reason=None):
        """Pause a campaign"""
        campaign = session.query(Campaign).get(campaign_id)
        if campaign:
            campaign.status = 'paused'
            campaign.paused_at = datetime.utcnow()
            
            # Log event
            log = CampaignLog(
                campaign_id=campaign_id,
                event_type='paused',
                event_description=f'Campaign paused: {reason}' if reason else 'Campaign paused'
            )
            session.add(log)
            session.commit()
            return True
        return False
    
    def complete_campaign(self, session, campaign_id):
        """Mark campaign as completed"""
        campaign = session.query(Campaign).get(campaign_id)
        if campaign:
            campaign.status = 'completed'
            campaign.completed_at = datetime.utcnow()
            campaign.calculate_metrics()
            
            # Log event
            log = CampaignLog(
                campaign_id=campaign_id,
                event_type='completed',
                event_description='Campaign completed successfully'
            )
            session.add(log)
            session.commit()
            return True
        return False
    
    def update_campaign_progress(self, session, campaign_id, **kwargs):
        """Update campaign progress metrics"""
        campaign = session.query(Campaign).get(campaign_id)
        if campaign:
            for key, value in kwargs.items():
                if hasattr(campaign, key):
                    current = getattr(campaign, key, 0) or 0
                    setattr(campaign, key, current + value)
            
            campaign.calculate_metrics()
            campaign.updated_at = datetime.utcnow()
            session.commit()
    
    # ========== Message Queue Operations ==========
    
    def queue_message(self, session, message_data):
        """Add message to queue"""
        message = MessageQueue(**message_data)
        session.add(message)
        session.commit()
        return message
    
    def bulk_queue_messages(self, session, messages_data):
        """Bulk add messages to queue"""
        messages = [MessageQueue(**data) for data in messages_data]
        session.bulk_save_objects(messages)
        session.commit()
        return len(messages)
    
    def get_pending_messages(self, session, limit=100):
        """Get pending messages from queue"""
        return session.query(MessageQueue).filter(
            MessageQueue.status == 'pending'
        ).order_by(
            MessageQueue.priority.desc(),
            MessageQueue.created_at
        ).limit(limit).all()
    
    def get_scheduled_messages(self, session):
        """Get messages ready to be sent"""
        now = datetime.utcnow()
        return session.query(MessageQueue).filter(
            MessageQueue.status == 'scheduled',
            MessageQueue.scheduled_at <= now
        ).order_by(
            MessageQueue.priority.desc()
        ).all()
    
    def mark_message_sent(self, session, message_id, success=True, error=None):
        """Mark message as sent or failed"""
        message = session.query(MessageQueue).get(message_id)
        if message:
            if success:
                message.status = 'sent'
                message.sent_at = datetime.utcnow()
            else:
                message.status = 'failed'
                message.failed_at = datetime.utcnow()
                message.failure_reason = error
                message.retry_count += 1
                
                # Schedule retry if possible
                if message.can_retry:
                    wait_time = min(300, 60 * (2 ** message.retry_count))  # Exponential backoff
                    message.retry_after = datetime.utcnow() + timedelta(seconds=wait_time)
                    message.status = 'pending'
            
            session.commit()
            return message
        return None
    
    def get_retry_messages(self, session):
        """Get messages ready for retry"""
        now = datetime.utcnow()
        return session.query(MessageQueue).filter(
            MessageQueue.status == 'pending',
            MessageQueue.retry_count > 0,
            MessageQueue.retry_after <= now
        ).all()
    
    # ========== Analytics Operations ==========
    
    def get_campaign_analytics(self, session, campaign_id):
        """Get detailed campaign analytics"""
        campaign = session.query(Campaign).get(campaign_id)
        if not campaign:
            return None
        
        # Calculate additional metrics
        total_members = session.query(CampaignMember).filter_by(
            campaign_id=campaign_id
        ).count()
        
        active_accounts = session.query(CampaignAccount).filter_by(
            campaign_id=campaign_id,
            is_active=True
        ).count()
        
        # Message status breakdown
        message_stats = session.query(
            MessageQueue.status,
            func.count(MessageQueue.id)
        ).filter(
            MessageQueue.campaign_id == campaign_id
        ).group_by(MessageQueue.status).all()
        
        # Response sentiment breakdown
        response_stats = session.query(
            Member.response_sentiment,
            func.count(Member.id)
        ).join(
            CampaignMember
        ).filter(
            CampaignMember.campaign_id == campaign_id,
            Member.response_received == True
        ).group_by(Member.response_sentiment).all()
        
        # Hourly performance
        hourly_stats = session.query(
            func.strftime('%H', MessageQueue.sent_at).label('hour'),
            func.count(MessageQueue.id).label('count'),
            func.avg(
                case([(MessageQueue.status == 'delivered', 1)], else_=0)
            ).label('success_rate')
        ).filter(
            MessageQueue.campaign_id == campaign_id,
            MessageQueue.sent_at.isnot(None)
        ).group_by('hour').all()
        
        return {
            'campaign': campaign.to_dict(),
            'total_members': total_members,
            'active_accounts': active_accounts,
            'message_status': dict(message_stats),
            'response_sentiment': dict(response_stats),
            'hourly_performance': [
                {'hour': h, 'count': c, 'success_rate': s * 100}
                for h, c, s in hourly_stats
            ]
        }
    
    def get_account_performance(self, session, account_id, days=7):
        """Get account performance metrics"""
        account = session.query(Account).get(account_id)
        if not account:
            return None
        
        since = datetime.utcnow() - timedelta(days=days)
        
        # Daily message counts
        daily_stats = session.query(
            func.date(MessageQueue.sent_at).label('date'),
            func.count(MessageQueue.id).label('total'),
            func.sum(
                case([(MessageQueue.status == 'delivered', 1)], else_=0)
            ).label('delivered'),
            func.sum(
                case([(MessageQueue.status == 'failed', 1)], else_=0)
            ).label('failed')
        ).filter(
            MessageQueue.account_id == account_id,
            MessageQueue.sent_at >= since
        ).group_by('date').all()
        
        # Health history
        health_history = session.query(AccountHealthLog).filter(
            AccountHealthLog.account_id == account_id,
            AccountHealthLog.recorded_at >= since
        ).order_by(AccountHealthLog.recorded_at).all()
        
        return {
            'account': account.to_dict(),
            'daily_stats': [
                {
                    'date': str(date),
                    'total': total,
                    'delivered': delivered,
                    'failed': failed,
                    'success_rate': (delivered / total * 100) if total > 0 else 0
                }
                for date, total, delivered, failed in daily_stats
            ],
            'health_history': [
                {
                    'timestamp': log.recorded_at.isoformat(),
                    'health_score': log.health_score,
                    'event': log.event_type
                }
                for log in health_history
            ]
        }
    
    # ========== Maintenance Operations ==========
    
    def cleanup_old_logs(self, session, days=30):
        """Clean up old logs and completed messages"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Delete old campaign logs
        deleted_logs = session.query(CampaignLog).filter(
            CampaignLog.created_at < cutoff
        ).delete()
        
        # Delete old completed messages
        deleted_messages = session.query(MessageQueue).filter(
            MessageQueue.status.in_(['sent', 'delivered', 'failed']),
            MessageQueue.sent_at < cutoff
        ).delete()
        
        # Delete old health logs
        deleted_health = session.query(AccountHealthLog).filter(
            AccountHealthLog.recorded_at < cutoff
        ).delete()
        
        session.commit()
        
        return {
            'campaign_logs': deleted_logs,
            'messages': deleted_messages,
            'health_logs': deleted_health
        }
    
    def optimize_database(self):
        """Optimize database performance"""
        with self.engine.connect() as conn:
            conn.execute("VACUUM")
            conn.execute("ANALYZE")
            conn.execute("REINDEX")
    
    def backup_database(self, backup_path=None):
        """Create database backup"""
        import shutil
        from datetime import datetime
        
        if backup_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f'backup_{timestamp}_{self.db_path}'
        
        shutil.copy2(self.db_path, backup_path)
        return backup_path
    
    def get_statistics(self, session):
        """Get overall database statistics"""
        stats = {
            'members': {
                'total': session.query(Member).count(),
                'contacted': session.query(Member).filter(Member.contacted_at.isnot(None)).count(),
                'responded': session.query(Member).filter(Member.response_received == True).count(),
            },
            'accounts': {
                'total': session.query(Account).count(),
                'active': session.query(Account).filter(Account.is_active == True).count(),
                'banned': session.query(Account).filter(Account.is_banned == True).count(),
            },
            'campaigns': {
                'total': session.query(Campaign).count(),
                'active': session.query(Campaign).filter(Campaign.status == 'running').count(),
                'completed': session.query(Campaign).filter(Campaign.status == 'completed').count(),
            },
            'messages': {
                'total': session.query(MessageQueue).count(),
                'pending': session.query(MessageQueue).filter(MessageQueue.status == 'pending').count(),
                'sent': session.query(MessageQueue).filter(MessageQueue.status == 'sent').count(),
                'failed': session.query(MessageQueue).filter(MessageQueue.status == 'failed').count(),
            }
        }
        return stats


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def initialize_database(db_path='telegram_automation.db'):
    """Initialize database with all tables and indexes"""
    db = DatabaseManager(db_path)
    
    # Create initial data if needed
    session = db.get_session()
    
    # Check if database is empty
    if session.query(Account).count() == 0:
        print("Database initialized successfully!")
        print("Tables created:")
        for table in Base.metadata.tables.keys():
            print(f"  - {table}")
    
    session.close()
    return db


if __name__ == "__main__":
    # Initialize database when module is run directly
    db = initialize_database()
    session = db.get_session()
    stats = db.get_statistics(session)
    
    print("\nDatabase Statistics:")
    for category, data in stats.items():
        print(f"\n{category.upper()}:")
        for key, value in data.items():
            print(f"  {key}: {value}")
    
    session.close()
    print("\n✅ Database layer complete - NO SHORTCUTS TAKEN!")