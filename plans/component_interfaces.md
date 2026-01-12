# Component Interface Specifications

## 1. Account Creation Manager

### Data Models
```python
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class CreationStatus(str, Enum):
    PENDING = "pending"
    CREATING_EMAIL = "creating_email"
    FETCHING_PROXY = "fetching_proxy"
    GENERATING_FINGERPRINT = "generating_fingerprint"
    REGISTERING_ACCOUNT = "registering_account"
    SOLVING_CAPTCHA = "solving_captcha"
    SETTING_UP_PROFILE = "setting_up_profile"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class CreationParams(BaseModel):
    """Parameters for account creation request"""
    target_country: Optional[str] = None
    email_service_preference: Optional[str] = None  # "gmail", "outlook", "yahoo", "auto"
    profile_gender: Optional[str] = None  # "male", "female", "random"
    profile_age_range: Optional[tuple[int, int]] = None  # (18, 35)
    make_private: bool = True
    additional_notes: Optional[str] = None

class AccountResult(BaseModel):
    task_id: str
    status: CreationStatus
    account_details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class CreationStatusResponse(BaseModel):
    task_id: str
    status: CreationStatus
    progress_percentage: float
    current_step: str
    estimated_completion: Optional[datetime] = None
    account_details: Optional[Dict[str, Any]] = None
```

### Interface Methods
```python
class AccountCreationManager:
    """Orchestrates the entire account creation process"""
    
    async def create_account(
        self, 
        creation_params: CreationParams
    ) -> AccountResult:
        """
        Initiate a new account creation request.
        Returns immediately with task ID and initial status.
        """
        pass
    
    async def get_status(
        self, 
        task_id: str
    ) -> CreationStatusResponse:
        """
        Get current status of a creation task.
        """
        pass
    
    async def cancel_creation(
        self, 
        task_id: str
    ) -> bool:
        """
        Cancel an in-progress creation task.
        Returns True if cancellation successful.
        """
        pass
    
    async def list_accounts(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List created accounts with optional filters.
        """
        pass
    
    async def retry_failed(
        self,
        task_id: str
    ) -> AccountResult:
        """
        Retry a failed account creation with same parameters.
        """
        pass
```

## 2. Email Service Manager

### Data Models
```python
class EmailAccount(BaseModel):
    email: str
    password: str
    service: str  # "gmail", "outlook", "yahoo", "temp"
    created_at: datetime
    verified: bool = False
    verification_link: Optional[str] = None
    inbox_count: int = 0
    last_checked: Optional[datetime] = None

class EmailMessage(BaseModel):
    sender: str
    subject: str
    body: str
    received_at: datetime
    links: List[str] = []
```

### Interface Methods
```python
class EmailServiceManager:
    """Manages creation and verification of email accounts"""
    
    async def create_email(
        self,
        service: Optional[str] = None
    ) -> EmailAccount:
        """
        Create a new email account using specified service.
        If service is None, auto-selects based on availability.
        """
        pass
    
    async def verify_email(
        self,
        email_account: EmailAccount
    ) -> bool:
        """
        Verify an email account (click verification link if needed).
        Returns True if verification successful.
        """
        pass
    
    async def get_verification_link(
        self,
        email_account: EmailAccount,
        timeout_seconds: int = 300
    ) -> Optional[str]:
        """
        Poll inbox for verification link from Twitter.
        Returns link if found within timeout.
        """
        pass
    
    async def check_inbox(
        self,
        email_account: EmailAccount,
        since: Optional[datetime] = None
    ) -> List[EmailMessage]:
        """
        Fetch new emails from inbox.
        """
        pass
    
    async def mark_as_read(
        self,
        email_account: EmailAccount,
        message_ids: List[str]
    ) -> bool:
        """
        Mark messages as read.
        """
        pass
    
    async def delete_email(
        self,
        email_account: EmailAccount
    ) -> bool:
        """
        Permanently delete email account.
        Use with caution.
        """
        pass
```

## 3. Proxy Manager

### Data Models
```python
class Proxy(BaseModel):
    address: str  # "ip:port"
    protocol: str  # "http", "https", "socks4", "socks5"
    country: Optional[str] = None
    anonymity: str  # "transparent", "anonymous", "elite"
    latency_ms: Optional[int] = None
    last_used: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    is_active: bool = True

class ProxySource(BaseModel):
    name: str
    url: str  # GitHub raw URL or API endpoint
    update_frequency_minutes: int = 30
    last_updated: Optional[datetime] = None

class ValidationResult(BaseModel):
    is_valid: bool
    latency_ms: Optional[int] = None
    anonymity_level: Optional[str] = None
    country: Optional[str] = None
    error_message: Optional[str] = None
```

### Interface Methods
```python
class ProxyManager:
    """Manages proxy sourcing, validation, and rotation"""
    
    async def fetch_proxies(
        self,
        source: Optional[ProxySource] = None
    ) -> List[Proxy]:
        """
        Fetch fresh proxies from specified source or all sources.
        """
        pass
    
    async def validate_proxy(
        self,
        proxy: Proxy,
        timeout_seconds: int = 10
    ) -> ValidationResult:
        """
        Validate proxy connectivity, anonymity, and latency.
        """
        pass
    
    async def get_proxy(
        self,
        country: Optional[str] = None,
        protocol: Optional[str] = None,
        min_anonymity: str = "anonymous"
    ) -> Proxy:
        """
        Get a fresh proxy matching criteria.
        Implements rotation based on usage history.
        """
        pass
    
    async def report_proxy_status(
        self,
        proxy: Proxy,
        success: bool,
        latency_ms: Optional[int] = None
    ) -> None:
        """
        Report success/failure of proxy usage for scoring.
        """
        pass
    
    async def refresh_sources(
        self
    ) -> int:
        """
        Refresh all proxy sources.
        Returns number of new proxies added.
        """
        pass
    
    async def get_proxy_stats(
        self
    ) -> Dict[str, Any]:
        """
        Get statistics about proxy pool.
        """
        pass
```

## 4. Device Fingerprint Generator

### Data Models
```python
class DeviceFingerprint(BaseModel):
    user_agent: str
    screen_resolution: str  # "1920x1080"
    color_depth: int  # 24
    timezone: str  # "America/New_York"
    language: str  # "en-US"
    platform: str  # "Win32"
    hardware_concurrency: int  # 8
    device_memory: int  # 8 (GB)
    
    # Canvas fingerprint
    canvas_hash: Optional[str] = None
    
    # WebGL fingerprint
    webgl_vendor: Optional[str] = None
    webgl_renderer: Optional[str] = None
    
    # Font enumeration
    fonts: List[str] = []
    
    # Plugin enumeration
    plugins: List[str] = []
    
    # Audio fingerprint
    audio_hash: Optional[str] = None
    
    # Generated metadata
    device_type: str  # "desktop", "mobile", "tablet"
    os: str  # "Windows 10", "macOS 12", "Android 11"
    browser: str  # "Chrome 120", "Firefox 115"
    browser_version: str  # "120.0.0.0"
    
    # Consistency markers
    generated_at: datetime
    consistency_token: str  # For matching across sessions
```

### Interface Methods
```python
class FingerprintGenerator:
    """Generates realistic device fingerprints"""
    
    async def generate_fingerprint(
        self,
        device_type: Optional[str] = None,
        country: Optional[str] = None
    ) -> DeviceFingerprint:
        """
        Generate a complete device fingerprint.
        If country provided, matches timezone/language.
        """
        pass
    
    async def validate_fingerprint(
        self,
        fingerprint: DeviceFingerprint
    ) -> bool:
        """
        Validate fingerprint for consistency and realism.
        """
        pass
    
    async def get_fingerprint_pool(
        self,
        count: int,
        device_type: Optional[str] = None
    ) -> List[DeviceFingerprint]:
        """
        Get multiple unique fingerprints for batch operations.
        """
        pass
    
    async def save_fingerprint(
        self,
        fingerprint: DeviceFingerprint
    ) -> str:
        """
        Save fingerprint to database for reuse.
        Returns fingerprint ID.
        """
        pass
    
    async def load_fingerprint(
        self,
        fingerprint_id: str
    ) -> Optional[DeviceFingerprint]:
        """
        Load previously saved fingerprint.
        """
        pass
```

## 5. CAPTCHA Solver

### Data Models
```python
class CaptchaSolution(BaseModel):
    solution: str
    solver_type: str  # "2captcha", "anticaptcha", "local_ml"
    solve_time_ms: int
    confidence: float  # 0.0 to 1.0
    cost_usd: Optional[float] = None

class CaptchaRequest(BaseModel):
    image_data: Optional[bytes] = None
    captcha_type: str  # "image", "recaptcha_v2", "recaptcha_v3", "hcaptcha"
    site_key: Optional[str] = None
    page_url: Optional[str] = None
    additional_params: Dict[str, Any] = {}
```

### Interface Methods
```python
class CaptchaSolver:
    """Solves CAPTCHAs using multiple strategies"""
    
    async def solve(
        self,
        request: CaptchaRequest
    ) -> CaptchaSolution:
        """
        Solve CAPTCHA using best available method.
        """
        pass
    
    async def solve_twitter_captcha(
        self,
        driver: Any  # WebDriver/Playwright context
    ) -> bool:
        """
        Detect and solve Twitter-specific CAPTCHAs.
        Returns True if solved successfully.
        """
        pass
    
    async def report_success_rate(
        self,
        solver_type: str,
        success: bool
    ) -> None:
        """
        Report success/failure for solver performance tracking.
        """
        pass
    
    async def get_solver_stats(
        self
    ) -> Dict[str, Any]:
        """
        Get statistics about solver performance and costs.
        """
        pass
    
    async def get_balance(
        self,
        solver_type: str
    ) -> float:
        """
        Get account balance for paid solver services.
        """
        pass
```

## 6. Twitter Automation Client

### Data Models
```python
class TwitterAccount(BaseModel):
    username: str
    email: str
    user_id: Optional[str] = None
    created_at: datetime
    auth_token: Optional[str] = None
    csrf_token: Optional[str] = None
    is_verified: bool = False
    is_private: bool = False
    profile_setup_complete: bool = False
    last_activity: Optional[datetime] = None

class ProfileData(BaseModel):
    full_name: str
    bio: str
    location: Optional[str] = None
    website: Optional[str] = None
    birth_date: Optional[datetime] = None
    profile_image_url: Optional[str] = None
    header_image_url: Optional[str] = None
    interests: List[str] = []
```

### Interface Methods
```python
class TwitterAutomationClient:
    """Automates interactions with Twitter/X"""
    
    async def register_account(
        self,
        email: str,
        fingerprint: DeviceFingerprint,
        proxy: Proxy
    ) -> TwitterAccount:
        """
        Register a new Twitter account.
        Returns account details on success.
        """
        pass
    
    async def verify_email(
        self,
        twitter_account: TwitterAccount,
        verification_link: str
    ) -> bool:
        """
        Complete email verification using provided link.
        """
        pass
    
    async def setup_profile(
        self,
        twitter_account: TwitterAccount,
        profile_data: ProfileData
    ) -> bool:
        """
        Set up profile information and images.
        """
        pass
    
    async def make_private(
        self,
        twitter_account: TwitterAccount
    ) -> bool:
        """
        Set account to private mode.
        """
        pass
    
    async def post_first_tweet(
        self,
        twitter_account: TwitterAccount,
        content: str
    ) -> bool:
        """
        Post initial tweet to establish account activity.
        """
        pass
    
    async def follow_suggestions(
        self,
        twitter_account: TwitterAccount,
        count: int = 10
    ) -> bool:
        """
        Follow suggested accounts to increase legitimacy.
        """
        pass
    
    async def check_account_status(
        self,
        twitter_account: TwitterAccount
    ) -> str:
        """
        Check if account is active, suspended, or limited.
        Returns status string.
        """
        pass
```

## 7. Profile Setup Service

### Data Models
```python
class ImageData(BaseModel):
    image_bytes: bytes
    mime_type: str  # "image/jpeg", "image/png"
    width: int
    height: int
    source: str  # "generated", "sourced", "template"

class GeneratedProfile(BaseModel):
    profile_data: ProfileData
    profile_image: Optional[ImageData] = None
    header_image: Optional[ImageData] = None
    interests: List[str] = []
    persona_description: str
```

### Interface Methods
```python
class ProfileSetupService:
    """Generates realistic profile data and images"""
    
    async def generate_profile(
        self,
        fingerprint: DeviceFingerprint,
        gender: Optional[str] = None,
        age_range: Optional[tuple[int, int]] = None
    ) -> GeneratedProfile:
        """
        Generate complete profile data including images.
        """
        pass
    
    async def generate_profile_image(
        self,
        gender: Optional[str] = None,
        age: Optional[int] = None,
        ethnicity: Optional[str] = None
    ) -> ImageData:
        """
        Generate or source profile picture.
        """
        pass
    
    async def generate_header_image(
        self,
        interests: List[str]
    ) -> ImageData:
        """
        Generate header image based on interests.
        """
        pass
    
    async def generate_bio(
        self,
        interests: List[str],
        personality_traits: Optional[List[str]] = None
    ) -> str:
        """
        Generate realistic bio text.
        """
        pass
    
    async def save_profile_assets(
        self,
        generated_profile: GeneratedProfile
    ) -> Dict[str, str]:
        """
        Save images to storage and return URLs.
        """
        pass
```

## 8. Database Schema

### Core Tables
```sql
-- accounts table
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    task_id VARCHAR(255) UNIQUE,
    username VARCHAR(255),
    email VARCHAR(255),
    email_service VARCHAR(50),
    password_hash VARCHAR(255),
    twitter_user_id VARCHAR(255),
    auth_token TEXT,
    csrf_token TEXT,
    profile_data JSONB,
    fingerprint_data JSONB,
    proxy_used JSONB,
    status VARCHAR(50),
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    last_checked TIMESTAMP,
    error_message TEXT,
    metadata JSONB
);

-- proxies table
CREATE TABLE proxies (
    id UUID PRIMARY KEY,
    address VARCHAR(255) UNIQUE,
    protocol VARCHAR(20),
    country VARCHAR(100),
    anonymity VARCHAR(50),
    latency_ms INTEGER,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_used TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    source VARCHAR(255),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- fingerprints table
CREATE TABLE fingerprints (
    id UUID PRIMARY KEY,
    fingerprint_data JSONB,
    device_type VARCHAR(50),
    os VARCHAR(100),
    browser VARCHAR(100),
    country VARCHAR(100),
    consistency_token VARCHAR(255),
    usage_count INTEGER DEFAULT 0,
    created_at TIMESTAMP,
    last_used TIMESTAMP
);

-- tasks table
CREATE TABLE tasks (
    id UUID PRIMARY KEY,
    task_id VARCHAR(255) UNIQUE,
    status VARCHAR(50),
    progress_percentage FLOAT,
    current_step VARCHAR(100),
    params JSONB,
    result JSONB,
    error_message TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    completed_at TIMESTAMP
);
```

## 9. API Endpoints

### REST API
```
POST   /api/v1/accounts/create     # Create new account
GET    /api/v1/accounts/{task_id}  # Get creation status
DELETE /api/v1/accounts/{task_id}  # Cancel creation
GET    /api/v1/accounts            # List accounts
GET    /api/v1/proxies/stats       # Get proxy statistics
GET    /api/v1/system/health       # System health check
POST   /api/v1/batch/create        # Batch account creation
```

### WebSocket Events
```
account.created        # Account creation completed
account.failed         # Account creation failed
account.status_update  # Status update during creation
proxy.refreshed        # Proxy pool refreshed
system.alert           # System alert/notification
```

## 10. Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/twitter_bot
REDIS_URL=redis://localhost:6379/0

# External Services
TWOCAPTCHA_API_KEY=your_api_key
GMAIL_API_CLIENT_ID=your_client_id
GMAIL_API_CLIENT_SECRET=your_client_secret
OUTLOOK_API_CLIENT_ID=your_client_id
OUTLOOK_API_CLIENT_SECRET=your_client_secret

# Twitter
TWITTER_REGISTRATION_DELAY_MIN=5
TWITTER_REGISTRATION_DELAY_MAX=30

# Proxy Settings
PROXY_SOURCES='["https://raw.githubusercontent.com/..."]'
PROXY_VALIDATION_TIMEOUT=10

# Security
ENCRYPTION_KEY=your_encryption_key
JWT_SECRET=your_jwt_secret
```

This interface specification provides a complete blueprint for implementing the automated Twitter account creation system with clear contracts between components.