# Data Flow Diagrams

## System‑Wide Data Flow

### Overview Flow
```mermaid
flowchart TD
    A[User Request] --> B{Dashboard UI}
    B --> C[API Gateway]
    C --> D[Account Creation Manager]
    
    subgraph Orchestration
        D --> E[Create Email Account]
        E --> F[Fetch/Validate Proxy]
        F --> G[Generate Fingerprint]
        G --> H[Register Twitter Account]
        H --> I[Solve CAPTCHA if needed]
        I --> J[Verify Email]
        J --> K[Setup Profile]
        K --> L[Finalize Account]
    end
    
    L --> M[(Database)]
    M --> N[Update Dashboard]
    N --> O[User Notification]
    
    subgraph External Services
        P[Email APIs]
        Q[Proxy Sources]
        R[Twitter/X]
        S[CAPTCHA Solvers]
        T[Image Storage]
    end
    
    E --> P
    F --> Q
    H --> R
    I --> S
    K --> T
```

## Component‑Level Data Flows

### 1. Email Account Creation Flow
```mermaid
flowchart TD
    A[Start Email Creation] --> B{Select Service}
    B -->|Auto| C[Choose Best Available]
    B -->|Manual| D[Use Specified Service]
    
    C --> E{Gmail Available?}
    E -->|Yes| F[Use Gmail API]
    E -->|No| G{Outlook Available?}
    G -->|Yes| H[Use Outlook API]
    G -->|No| I[Use Temp‑mail API]
    
    F --> J[Generate Credentials]
    H --> J
    I --> J
    
    J --> K[Create Account via API]
    K --> L{Success?}
    L -->|Yes| M[Store Credentials]
    L -->|No| N[Fallback Service]
    N --> E
    
    M --> O[Verify Account]
    O --> P[Monitor Inbox]
    P --> Q[Return Email Account]
```

### 2. Proxy Acquisition & Validation Flow
```mermaid
flowchart LR
    A[Proxy Manager] --> B[Fetch Proxy Lists]
    B --> C[Parse & Extract Proxies]
    C --> D[Store Raw Proxies]
    D --> E[Validation Queue]
    
    subgraph Validation Workers
        F[Worker 1]
        G[Worker 2]
        H[Worker N]
    end
    
    E --> F
    E --> G
    E --> H
    
    F --> I[Test Connectivity]
    G --> I
    H --> I
    
    I --> J[Check Anonymity]
    J --> K[Measure Latency]
    K --> L{Valid?}
    
    L -->|Yes| M[Add to Active Pool]
    L -->|No| N[Discard/Blacklist]
    
    M --> O[(Proxy Database)]
    N --> P[(Blacklist)]
    
    O --> Q[Rotation Algorithm]
    Q --> R[Return Proxy to Client]
```

### 3. Device Fingerprint Generation Flow
```mermaid
flowchart TD
    A[Generate Request] --> B{Country Specified?}
    B -->|Yes| C[Load Country Profile]
    B -->|No| D[Select Random Country]
    
    C --> E[Determine Timezone/Language]
    D --> E
    
    E --> F[Select Device Type]
    F --> G[Generate User‑Agent]
    G --> H[Generate Screen Resolution]
    H --> I[Generate Canvas Fingerprint]
    I --> J[Generate WebGL Fingerprint]
    J --> K[Generate Font List]
    K --> L[Generate Plugin List]
    L --> M[Generate Audio Fingerprint]
    
    M --> N[Assemble Fingerprint]
    N --> O[Validate Consistency]
    O --> P{Valid?}
    P -->|Yes| Q[Store Fingerprint]
    P -->|No| R[Regenerate]
    R --> F
    
    Q --> S[Return Fingerprint]
```

### 4. Twitter Account Registration Flow
```mermaid
sequenceDiagram
    participant CM as Creation Manager
    participant TC as Twitter Client
    participant TW as Twitter/X
    participant CS as CAPTCHA Solver
    participant EM as Email Manager
    
    CM->>TC: Register with(email, fingerprint, proxy)
    TC->>TW: Load registration page
    TW-->>TC: Registration form
    TC->>TC: Fill form with generated data
    TC->>TW: Submit form
    
    alt CAPTCHA Present
        TW-->>TC: CAPTCHA challenge
        TC->>CS: Solve CAPTCHA
        CS-->>TC: CAPTCHA solution
        TC->>TW: Submit with solution
    end
    
    TW-->>TC: Email verification required
    TC->>CM: Verification required
    CM->>EM: Get verification link
    EM-->>CM: Verification link
    CM->>TC: Use verification link
    TC->>TW: Complete verification
    
    TW-->>TC: Account created successfully
    TC->>CM: Return account credentials
```

### 5. CAPTCHA Solving Flow
```mermaid
flowchart TD
    A[CAPTCHA Detected] --> B{Type Identification}
    B -->|Image CAPTCHA| C[Extract Image]
    B -->|reCAPTCHA v2| D[Extract sitekey]
    B -->|hCAPTCHA| E[Extract hCAPTCHA params]
    
    C --> F[Send to 2Captcha]
    D --> F
    E --> F
    
    F --> G[Wait for Solution]
    G --> H[Receive Solution]
    
    H --> I[Validate Solution]
    I --> J{Valid?}
    J -->|Yes| K[Use Solution]
    J -->|No| L[Retry with Different Solver]
    
    L --> M[Try Anti‑Captcha]
    M --> N{Success?}
    N -->|Yes| K
    N -->|No| O[Fallback: ML Model]
    
    O --> P[Local CAPTCHA Recognition]
    P --> Q{Confidence > 0.8?}
    Q -->|Yes| K
    Q -->|No| R[Mark as Failed]
```

### 6. Profile Setup Flow
```mermaid
flowchart TD
    A[Start Profile Setup] --> B[Generate Profile Data]
    B --> C{Generate Profile Image}
    C -->|AI Generation| D[Call Stable Diffusion API]
    C -->|Sourced| E[Fetch from Unsplash API]
    
    D --> F[Validate Image]
    E --> F
    
    F --> G{Image Quality OK?}
    G -->|Yes| H[Upload to Storage]
    G -->|No| C
    
    H --> I[Generate Header Image]
    I --> J[Upload to Storage]
    
    J --> K[Generate Bio Text]
    K --> L[Assemble Profile Data]
    
    L --> M[Apply to Twitter Account]
    M --> N[Set Privacy Settings]
    N --> O[Post Initial Tweet]
    O --> P[Follow Suggestions]
    P --> Q[Profile Setup Complete]
```

## Error Handling & Retry Flow

```mermaid
flowchart TD
    A[Operation Start] --> B[Execute Operation]
    B --> C{Success?}
    C -->|Yes| D[Mark Success]
    
    C -->|No| E[Error Analysis]
    E --> F{Error Type}
    
    F -->|Transient<br/>Network| G[Wait & Retry]
    F -->|Service Limit| H[Switch Service]
    F -->|Permanent| I[Mark Failed]
    
    G --> J[Increment Retry Count]
    J --> K{Max Retries?}
    K -->|No| B
    K -->|Yes| I
    
    H --> L[Select Alternative]
    L --> B
    
    I --> M[Log Failure]
    M --> N[Notify User]
```

## Data Storage Flow

### Account Data Persistence
```mermaid
flowchart LR
    A[Account Created] --> B[Encrypt Sensitive Data]
    B --> C[Store in PostgreSQL]
    C --> D[Index for Quick Retrieval]
    D --> E[Cache in Redis]
    
    E --> F[API Access]
    F --> G[Dashboard Display]
    
    H[Profile Images] --> I[Upload to S3]
    I --> J[Store URLs in DB]
    J --> K[CDN Distribution]
```

### Proxy Data Lifecycle
```mermaid
flowchart TD
    A[Proxy Source] --> B[Raw Proxy List]
    B --> C[Validation Queue]
    C --> D[Validation Process]
    D --> E{Valid Proxy?}
    
    E -->|Yes| F[Store in Active Pool]
    E -->|No| G[Store in Invalid Pool]
    
    F --> H[Rotational Usage]
    H --> I[Success/Failure Tracking]
    I --> J{Success Rate < Threshold?}
    
    J -->|Yes| K[Move to Degraded Pool]
    J -->|No| H
    
    K --> L[Re‑validation]
    L --> M{Still Valid?}
    M -->|Yes| F
    M -->|No| G
    
    G --> N[Periodic Cleanup]
```

## Real‑Time Monitoring Flow

### Dashboard Updates
```mermaid
sequenceDiagram
    participant User
    participant Dashboard
    participant API
    participant WebSocket
    participant Worker
    participant DB
    
    User->>Dashboard: Open Dashboard
    Dashboard->>API: Fetch initial data
    API->>DB: Query accounts, proxies, stats
    DB-->>API: Return data
    API-->>Dashboard: Initial render
    
    Dashboard->>WebSocket: Subscribe to updates
    
    Worker->>DB: Update account status
    DB->>WebSocket: Notify status change
    WebSocket->>Dashboard: Push update
    Dashboard->>Dashboard: Update UI
    
    loop Continuous Updates
        Worker->>DB: Update metrics
        DB->>WebSocket: Push metrics
        WebSocket->>Dashboard: Update charts
    end
```

## Batch Processing Flow

### Mass Account Creation
```mermaid
flowchart TD
    A[Batch Request] --> B[Parse Parameters]
    B --> C[Create Task Queue]
    C --> D[Distribute to Workers]
    
    subgraph Worker Pool
        E[Worker 1]
        F[Worker 2]
        G[Worker N]
    end
    
    D --> E
    D --> F
    D --> G
    
    E --> H[Process Single Account]
    F --> H
    G --> H
    
    H --> I[Update Progress]
    I --> J[(Progress Database)]
    
    J --> K[Dashboard Updates]
    K --> L[User Monitoring]
    
    H --> M{All Complete?}
    M -->|Yes| N[Generate Report]
    M -->|No| H
    
    N --> O[Send Completion Notification]
```

## Security Data Flow

### Credential Handling
```mermaid
flowchart TD
    A[Raw Credentials] --> B[Encryption Service]
    B --> C[Generate Encryption Key]
    C --> D[Encrypt Credentials]
    D --> E[Store in Secure Database]
    
    E --> F[Access Request]
    F --> G[Authentication Check]
    G --> H{Authorized?}
    H -->|Yes| I[Retrieve & Decrypt]
    H -->|No| J[Access Denied]
    
    I --> K[Temporary Use]
    K --> L[Clear Memory]
    
    M[Key Rotation] --> N[Re‑encrypt All Credentials]
    N --> O[Update Database]
```

## Integration Points Data Flow

### External APIs Integration
```mermaid
flowchart LR
    A[Our System] --> B[Rate Limiter]
    B --> C[API Client]
    C --> D[Request Transformer]
    D --> E[External API]
    E --> F[Response Parser]
    F --> G[Error Handler]
    G --> H[Data Normalizer]
    H --> I[Our Data Model]
    
    G --> J{Error?}
    J -->|Yes| K[Retry Logic]
    K --> C
    J -->|No| I
```

These data flow diagrams illustrate how information moves through the system, highlighting critical integration points, error handling pathways, and data transformation steps. Each diagram corresponds to a major system component and shows the sequence of operations required to accomplish specific tasks within the automated Twitter account creation system.