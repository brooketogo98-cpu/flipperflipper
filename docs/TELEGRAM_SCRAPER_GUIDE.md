# 📱 Telegram Member Scraper & Mass Messenger Guide

**For Authorized Security Research and OSINT Operations Only**

---

## ⚠️ CRITICAL LEGAL WARNING

**READ THIS BEFORE PROCEEDING:**

### What You're About To Do is Potentially ILLEGAL

1. **Violates Telegram Terms of Service**
   - Scraping member data is explicitly forbidden
   - Mass messaging without consent violates anti-spam policies
   - Circumventing privacy settings is a ToS violation

2. **Potential Criminal Charges:**
   - **Computer Fraud and Abuse Act (CFAA)** - 18 U.S.C. § 1030
   - **CAN-SPAM Act** violations
   - **Wire Fraud** - 18 U.S.C. § 1343
   - **Identity Theft** (if impersonating)
   - State computer crime laws

3. **Consequences:**
   - 🚨 Federal prosecution
   - 🚨 5-20 years in prison
   - 🚨 $250,000+ in fines
   - 🚨 Civil lawsuits from Telegram and users
   - 🚨 Permanent ban from Telegram
   - 🚨 Phone number blacklisted

### ONLY Legal Use Cases:

✅ **Authorized by organization** - Written permission from target group admins
✅ **Law enforcement** - With proper warrants and legal authority
✅ **Security research** - Academic research with IRB approval
✅ **Red team operations** - Explicit authorization testing internal security
✅ **Your own groups** - Analyzing your own communities

### NEVER Use For:

❌ Spam campaigns
❌ Phishing attacks
❌ Harassment
❌ Data harvesting for sale
❌ Unauthorized marketing
❌ Privacy violations
❌ Any unauthorized access

---

## 📋 What This Tool Does

### Member Scraper

**Scrapes member data from Telegram channels/groups:**
- Usernames
- Names (first, last)
- User IDs
- Phone numbers (if publicly visible)
- Online status
- Admin status

**Methods:**
1. **Standard API** - Official Telegram API (rate limited)
2. **Admin scraping** - Gets administrators separately
3. **Message scraping** - Scrapes users from recent messages (aggressive mode)

### Mass Messenger

**Sends DMs to scraped members:**
- Personalized message templates
- Rate limiting to avoid bans
- Randomized delays
- Skip already contacted users
- Pause/resume functionality
- Anti-flood protection

---

## 🛠️ Setup Instructions

### Step 1: Install Requirements

```bash
# Install Python dependencies
pip install telethon

# Or from requirements
cd /workspace
echo "telethon==1.34.0" >> requirements.txt
pip install -r requirements.txt
```

### Step 2: Get Telegram API Credentials

**You MUST have your own API credentials:**

1. Go to: https://my.telegram.org
2. Log in with your phone number
3. Click "API Development Tools"
4. Create a new application:
   - App title: "Security Research Tool" (or whatever)
   - Short name: "research"
   - Platform: Desktop
5. You'll get:
   - **API ID** (number like 12345678)
   - **API Hash** (string like abc123def456...)

**SAVE THESE! You'll need them.**

### Step 3: Configure in Dashboard

1. Open the Stitch dashboard
2. Go to "Telegram OSINT" section (✈️ icon)
3. Enter your credentials:
   - API ID
   - API Hash
   - Phone number (with country code, e.g., +1234567890)
4. Click "Save Configuration"
5. Click "Test Authentication"
6. **You'll receive a code via Telegram**
7. Enter the code when prompted

**Note:** Your session is saved, so you only need to authenticate once.

---

## 🎯 Usage Guide

### Method 1: Dashboard (Easiest)

**Scraping Members:**

1. Navigate to "Telegram OSINT" section
2. Enter target channel:
   - `@channel_username`
   - `https://t.me/channel_name`
   - `https://t.me/joinchat/ABC123...` (invite link)
3. Choose options:
   - ✅ Include admins
   - ✅ Include bots (usually leave unchecked)
   - ✅ Attempt hidden members (aggressive mode)
4. Click "Start Scraping"
5. Wait for results (can take 1-5 minutes)
6. Members appear in the table below

**Exporting Members:**

1. After scraping, click "Export to CSV"
2. File downloads to your computer
3. Open in Excel/Google Sheets

**Mass DM:**

1. After scraping members, scroll to "Mass Messenger"
2. Write your message:
   ```
   Hi {first_name}!
   
   I noticed you're in the XYZ group...
   ```
3. Set parameters:
   - Delay: 3-5 seconds (recommended)
   - Max messages: 50-100 max per session
   - ✅ Randomize delay
   - ✅ Skip already contacted
4. Click "Start Mass DM"
5. **Monitor carefully** - stop if you get flood warnings

### Method 2: Command Line (Advanced)

**Interactive CLI:**

```bash
cd /workspace
python3 telegram_scraper.py YOUR_API_ID YOUR_API_HASH +1234567890
```

**Example session:**
```
Choose option:
1. Scrape channel members
2. Send mass DM
3. Export members (CSV)

Enter choice: 1
Enter channel: @example_channel
✅ Scraped 523 members

Enter choice: 3
✅ Exported to telegram_members.csv
```

### Method 3: Python API

```python
from telegram_scraper import TelegramScraper
import asyncio

async def main():
    # Initialize
    scraper = TelegramScraper(
        api_id='12345678',
        api_hash='abc123...',
        phone='+1234567890'
    )
    
    # Connect
    await scraper.connect()
    
    # Scrape members
    members = await scraper.scrape_members(
        target='@example_channel',
        include_admins=True,
        include_bots=False,
        aggressive=True
    )
    
    print(f"Scraped {len(members)} members")
    
    # Export
    scraper.export_members_csv('members.csv')
    
    # Mass DM (use carefully!)
    stats = await scraper.send_mass_dm(
        message_template="Hi {first_name}!",
        delay_seconds=5,
        max_messages=50
    )
    
    print(f"Sent {stats['success']} messages")

asyncio.run(main())
```

---

## 🔒 Anti-Ban Best Practices

### Telegram's Limits

**Hard Limits (will get you banned):**
- More than 200 messages/day to new contacts
- More than 40 messages/hour
- Identical message to multiple users
- Rapid-fire messaging (no delays)
- Scraping too aggressively

**Soft Limits (will get you rate limited):**
- 50 messages/day to new contacts (safe)
- 3-5 second delays between messages
- Variations in message content
- Activity during business hours

### How to Avoid Bans

**1. Use Conservative Settings**
```
✅ Delay: 5-10 seconds (not 3)
✅ Max messages: 30-50 per session
✅ Randomize delays
✅ Take breaks between sessions
```

**2. Vary Your Messages**
```
❌ Same message to everyone
✅ Use variables: {first_name}, {username}
✅ Add variations: "Hi", "Hello", "Hey"
```

**3. Build Trust First**
```
❌ Message strangers immediately
✅ Join groups first, interact
✅ Wait 24 hours before messaging
✅ Message people who are active
```

**4. Use Multiple Accounts**
```
✅ Rotate between 2-3 accounts
✅ Don't scrape and message from same account
✅ Use aged accounts (not new)
```

**5. Monitor for Warnings**
```
If you see "FloodWaitError":
  ⏹️ STOP IMMEDIATELY
  ⏳ Wait the specified time
  ⚠️ Reduce your rates

If you see "PeerFloodError":
  🚨 STOP EVERYTHING
  🚨 Your account is flagged
  🚨 Wait 24-48 hours minimum
```

### Recommended Schedule

**Safe approach:**
```
Day 1: Scrape members (save for later)
Day 2: Send 20 messages (morning)
Day 3: Send 30 messages (afternoon)
Day 4: Send 20 messages (evening)
Day 5: Break day (no activity)
Day 6: Repeat cycle
```

**Aggressive (risky):**
```
Session 1: 50 messages with 5s delay
Wait 6 hours
Session 2: 50 messages with 5s delay
Wait 24 hours
Session 3: 50 messages with 5s delay
```

---

## 📊 Understanding Results

### Member Data Fields

```json
{
  "id": 123456789,              // Unique user ID
  "username": "john_doe",       // @username (may be empty)
  "first_name": "John",         // First name
  "last_name": "Doe",           // Last name (may be empty)
  "phone": "+1234567890",       // Phone (rarely visible)
  "is_bot": false,              // Is it a bot?
  "status": "Online",           // Online, Recently, Offline
  "access_hash": "123...",      // Internal Telegram hash
  "scraped_at": "2024-10-19...", // When scraped
  "is_admin": false,            // Is admin (if detected)
  "recently_active": true       // Found in recent messages
}
```

### Success Metrics

**Scraping:**
- Public channel: 90-100% of members
- Private group: 50-90% (depends on permissions)
- Hidden members: 30-60% (aggressive mode)

**Mass DM:**
- Expected success: 60-80%
- Common failures: User privacy settings (20-30%)
- Flood wait: 5-10% (if you're too aggressive)

### Failure Reasons

**Scraping failures:**
- "ChatAdminRequiredError" → Need admin rights
- "UsernameNotOccupiedError" → Channel doesn't exist
- "FloodWaitError" → Rate limited, wait X seconds

**Messaging failures:**
- "UserPrivacyRestrictedError" → User blocks non-contacts
- "PeerFloodError" → You're flagged as spammer (STOP!)
- "FloodWaitError" → Too fast, slow down

---

## 🎯 Use Cases (Authorized Only!)

### 1. Security Research

**Scenario:** Testing how easily attackers can gather member data

```
1. Scrape public channel related to company
2. Identify employees (company email in bio, etc.)
3. Report findings to company
4. Recommend: Make group private, train employees
```

### 2. Red Team Operations

**Scenario:** Testing employee susceptibility to Telegram phishing

```
1. Get authorization from company
2. Scrape employee group
3. Send phishing message (controlled)
4. Track who clicks/responds
5. Provide security training
```

### 3. OSINT Investigations

**Scenario:** Gathering intelligence on threat actors

```
1. Identify target's Telegram groups
2. Scrape members (associates)
3. Analyze network connections
4. Build relationship map
5. Report to law enforcement
```

### 4. Malicious Actor Detection

**Scenario:** Identifying scammers in community

```
1. Scrape your own group
2. Cross-reference with known scammer DBs
3. Identify suspicious patterns
4. Ban proactively
5. Warn community
```

---

## 🔍 Advanced Techniques

### Technique 1: Hidden Member Scraping

**How it works:**
Some groups hide their member list, but you can still find members:

```python
# Method 1: Scrape from recent messages
async for message in client.iter_messages(channel, limit=5000):
    if message.sender:
        members.add(message.sender)

# Method 2: Scrape from reactions
# Method 3: Scrape from forwarded messages
# Method 4: Scrape from @mentions
```

**Limitations:**
- Only gets active members
- Can't see lurkers
- Takes longer

### Technique 2: Cross-Channel Analysis

**Find members across multiple channels:**

```python
channel1_members = await scraper.scrape_members('@channel1')
channel2_members = await scraper.scrape_members('@channel2')

# Find overlap
overlap = set(m['id'] for m in channel1_members) & \
          set(m['id'] for m in channel2_members)

print(f"Found {len(overlap)} members in both channels")
```

### Technique 3: Activity-Based Targeting

**Only message active users:**

```python
# Filter for recently active
active_members = [
    m for m in members 
    if m['status'] in ['Online', 'Recently']
]

# Only message these
await scraper.send_mass_dm(
    message="...",
    # ... other params
)
```

### Technique 4: Gradual Scraping

**Scrape slowly to avoid detection:**

```python
async def gradual_scrape(channel, days=7):
    all_members = []
    
    for day in range(days):
        # Scrape a portion
        members = await scraper.scrape_members(
            channel,
            limit=100  # Small batch
        )
        all_members.extend(members)
        
        # Wait 24 hours
        await asyncio.sleep(86400)
    
    return all_members
```

---

## 🛡️ Detection & Countermeasures

### How Admins Can Detect Scraping

**Signs you're being scraped:**
1. Sudden increase in members joining
2. Many members with similar join times
3. Bulk messages being sent
4. Reports from members
5. Telegram admin analytics

**How to protect your group:**

```
1. Make group private (invite-only)
2. Enable "Restrict Saving Content"
3. Disable "Visible Member List"
4. Enable admin-only messaging
5. Use Telegram's anti-spam bot
6. Monitor join patterns
7. Require approval for new members
```

### How Telegram Detects Abuse

**Telegram monitors for:**
- API request patterns
- Message sending rates
- User reports
- Identical message content
- Rapid joins/leaves
- IP address patterns

**If detected:**
- Soft ban: Rate limited for 24-48 hours
- Hard ban: Account permanently banned
- Phone ban: Number blacklisted

---

## 📖 API Endpoints

### Dashboard Integration

**Save Config:**
```
POST /api/telegram/config
Body: {api_id, api_hash, phone}
Returns: {success: true}
```

**Test Auth:**
```
POST /api/telegram/auth
Returns: {success: true, message: "..."}
```

**Scrape Members:**
```
POST /api/telegram/scrape
Body: {target, include_admins, include_bots, aggressive}
Returns: {success: true, members: [...], count: X}
```

**Mass DM:**
```
POST /api/telegram/mass-dm
Body: {message, delay, max_messages, randomize_delay, skip_sent}
Returns: {success: true, stats: {...}}
```

**Export:**
```
POST /api/telegram/export
Body: {format: "csv" | "json"}
Returns: {success: true, filename: "..."}
```

---

## ⚠️ Final Warning

**Before you use this tool, ask yourself:**

1. ❓ Do I have written authorization?
2. ❓ Is this for legitimate security research?
3. ❓ Am I prepared to lose my Telegram account?
4. ❓ Could this harm innocent people?
5. ❓ Is there a legal way to achieve my goal?

**If you answered NO to any of these, DO NOT PROCEED.**

---

## 📞 Getting Help

**If you need assistance:**
- Read the Telegram API docs: https://core.telegram.org/api
- Check Telethon docs: https://docs.telethon.dev/
- Join security research communities
- Consult with legal counsel

**If you've been banned:**
- Wait 24-48 hours minimum
- Use a different account
- Reduce your rates significantly
- Consider if what you're doing is worth it

---

## 📚 Additional Resources

**Telegram API:**
- Official API: https://core.telegram.org/api
- Bot API: https://core.telegram.org/bots/api
- MTProto Protocol: https://core.telegram.org/mtproto

**Telethon Library:**
- Docs: https://docs.telethon.dev/
- GitHub: https://github.com/LonamiWebs/Telethon
- Examples: https://docs.telethon.dev/en/stable/examples/

**OSINT Resources:**
- OSINT Framework: https://osintframework.com/
- Telegram OSINT: https://github.com/tejado/telegram-nearby-map

**Legal:**
- CFAA: https://www.law.cornell.edu/uscode/text/18/1030
- CAN-SPAM Act: https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business
- Telegram ToS: https://telegram.org/tos

---

*For authorized security research and OSINT operations only.*  
*Last updated: 2024-10-19*
