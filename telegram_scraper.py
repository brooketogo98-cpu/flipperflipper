#!/usr/bin/env python3
"""
Telegram Member Scraper and Mass Messenger
For authorized security research and OSINT operations only

⚠️ LEGAL WARNING:
- This violates Telegram's Terms of Service
- May be illegal in your jurisdiction without proper authorization
- Your Telegram account WILL be banned if you abuse this
- Use ONLY with explicit permission for security research

Requirements:
    pip install telethon
"""

import os
import json
import time
import csv
import random
from datetime import datetime
from telethon import TelegramClient, events
from telethon.tl.functions.channels import GetParticipantsRequest
from telethon.tl.types import ChannelParticipantsSearch, ChannelParticipantsAdmins
from telethon.tl.types import UserStatusOnline, UserStatusOffline, UserStatusRecently
from telethon.errors import (
    FloodWaitError, 
    UserPrivacyRestrictedError, 
    ChatAdminRequiredError,
    UsernameNotOccupiedError,
    PeerFloodError
)

class TelegramScraper:
    """
    Telegram member scraper with anti-ban measures
    """
    
    def __init__(self, api_id, api_hash, phone):
        """
        Initialize Telegram client
        
        Args:
            api_id: Telegram API ID (from my.telegram.org)
            api_hash: Telegram API Hash
            phone: Phone number with country code
        """
        self.api_id = api_id
        self.api_hash = api_hash
        self.phone = phone
        
        # Session file
        session_file = f"telegram_session_{phone.replace('+', '')}"
        self.client = TelegramClient(session_file, api_id, api_hash)
        
        self.members = []
        self.sent_users = set()
        self.is_running = False
        self.is_paused = False
        
    async def connect(self):
        """Connect and authenticate to Telegram"""
        await self.client.connect()
        
        if not await self.client.is_user_authorized():
            print(f"Sending code to {self.phone}...")
            await self.client.send_code_request(self.phone)
            
            # In production, you'd need to handle 2FA
            code = input("Enter the code you received: ")
            await self.client.sign_in(self.phone, code)
            
        print("✅ Successfully authenticated!")
        return True
    
    async def get_entity_from_link(self, target):
        """
        Get entity from username or invite link
        
        Args:
            target: @username or https://t.me/... link
            
        Returns:
            Channel/Group entity
        """
        # Clean up the target
        if 'joinchat/' in target or 't.me/+' in target:
            # Invite link
            invite_hash = target.split('/')[-1].replace('+', '')
            entity = await self.client.get_entity(f"https://t.me/joinchat/{invite_hash}")
        elif 't.me/' in target:
            # Public link
            username = target.split('t.me/')[-1].split('?')[0]
            entity = await self.client.get_entity(username)
        elif target.startswith('@'):
            # Username
            entity = await self.client.get_entity(target)
        else:
            # Try as-is
            entity = await self.client.get_entity(target)
        
        return entity
    
    async def scrape_members(
        self, 
        target, 
        include_admins=True, 
        include_bots=False,
        aggressive=True,
        progress_callback=None
    ):
        """
        Scrape members from a channel or group
        
        Args:
            target: Channel username or link
            include_admins: Include administrators
            include_bots: Include bot accounts
            aggressive: Try multiple methods to get hidden members
            progress_callback: Function to call with progress updates
            
        Returns:
            List of member dicts
        """
        print(f"🔍 Scraping members from: {target}")
        
        try:
            # Get the channel/group entity
            entity = await self.get_entity_from_link(target)
            
            if progress_callback:
                progress_callback(f"Found: {entity.title}", 0)
            
            all_members = []
            offset = 0
            limit = 200  # Telegram's max per request
            
            # Method 1: Standard participant request
            print("📋 Method 1: Standard participant scraping...")
            while True:
                try:
                    participants = await self.client(GetParticipantsRequest(
                        entity,
                        ChannelParticipantsSearch(''),
                        offset,
                        limit,
                        hash=0
                    ))
                    
                    if not participants.users:
                        break
                    
                    for user in participants.users:
                        # Filter bots if needed
                        if not include_bots and user.bot:
                            continue
                        
                        member_data = self._extract_user_data(user)
                        all_members.append(member_data)
                    
                    offset += len(participants.users)
                    
                    if progress_callback:
                        progress_callback(
                            f"Scraped {len(all_members)} members...",
                            len(all_members)
                        )
                    
                    # Rate limiting
                    await asyncio.sleep(1)
                    
                    if len(participants.users) < limit:
                        break
                        
                except ChatAdminRequiredError:
                    print("❌ Admin privileges required for this channel")
                    break
                except FloodWaitError as e:
                    print(f"⚠️ Flood wait: {e.seconds} seconds")
                    if progress_callback:
                        progress_callback(f"Rate limited, waiting {e.seconds}s", len(all_members))
                    await asyncio.sleep(e.seconds)
            
            # Method 2: Scrape from admins (if allowed)
            if include_admins and aggressive:
                print("📋 Method 2: Scraping administrators...")
                try:
                    admins = await self.client(GetParticipantsRequest(
                        entity,
                        ChannelParticipantsAdmins(),
                        0,
                        100,
                        hash=0
                    ))
                    
                    for user in admins.users:
                        if not any(m['id'] == user.id for m in all_members):
                            member_data = self._extract_user_data(user)
                            member_data['is_admin'] = True
                            all_members.append(member_data)
                    
                except Exception as e:
                    print(f"⚠️ Could not scrape admins: {e}")
            
            # Method 3: Scrape from recent messages (gets active users)
            if aggressive:
                print("📋 Method 3: Scraping from recent messages...")
                try:
                    async for message in self.client.iter_messages(entity, limit=1000):
                        if message.sender:
                            user = message.sender
                            if not any(m['id'] == user.id for m in all_members):
                                if include_bots or not user.bot:
                                    member_data = self._extract_user_data(user)
                                    member_data['recently_active'] = True
                                    all_members.append(member_data)
                        
                        # Progress update every 100 messages
                        if len(all_members) % 100 == 0 and progress_callback:
                            progress_callback(
                                f"Scraped {len(all_members)} members (scanning messages)...",
                                len(all_members)
                            )
                except Exception as e:
                    print(f"⚠️ Could not scrape from messages: {e}")
            
            self.members = all_members
            
            if progress_callback:
                progress_callback(f"✅ Complete! Scraped {len(all_members)} members", len(all_members))
            
            print(f"✅ Successfully scraped {len(all_members)} members")
            return all_members
            
        except UsernameNotOccupiedError:
            error = "❌ Channel/group not found"
            print(error)
            if progress_callback:
                progress_callback(error, 0)
            return []
        except Exception as e:
            error = f"❌ Error: {str(e)}"
            print(error)
            if progress_callback:
                progress_callback(error, 0)
            return []
    
    def _extract_user_data(self, user):
        """Extract relevant data from user object"""
        # Determine online status
        status = "Unknown"
        if hasattr(user, 'status'):
            if isinstance(user.status, UserStatusOnline):
                status = "Online"
            elif isinstance(user.status, UserStatusRecently):
                status = "Recently"
            elif isinstance(user.status, UserStatusOffline):
                status = "Offline"
        
        return {
            'id': user.id,
            'username': user.username or '',
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'phone': user.phone or '',
            'is_bot': user.bot if hasattr(user, 'bot') else False,
            'status': status,
            'access_hash': user.access_hash,
            'scraped_at': datetime.now().isoformat()
        }
    
    async def send_mass_dm(
        self,
        message_template,
        delay_seconds=3,
        max_messages=50,
        randomize_delay=True,
        skip_sent=True,
        progress_callback=None
    ):
        """
        Send mass DMs to scraped members
        
        Args:
            message_template: Message with variables {username}, {first_name}, etc.
            delay_seconds: Delay between messages
            max_messages: Maximum messages to send in this session
            randomize_delay: Add random variation to delay
            skip_sent: Skip users already messaged
            progress_callback: Function for progress updates
            
        Returns:
            Dict with stats
        """
        if not self.members:
            print("❌ No members loaded. Scrape first!")
            return {'success': 0, 'failed': 0, 'skipped': 0}
        
        self.is_running = True
        stats = {
            'success': 0,
            'failed': 0,
            'skipped': 0,
            'flood_wait': 0
        }
        
        print(f"📨 Starting mass DM to {len(self.members)} members...")
        
        for idx, member in enumerate(self.members):
            # Check if should stop
            if not self.is_running:
                print("⏹️ Stopped by user")
                break
            
            # Check if paused
            while self.is_paused:
                await asyncio.sleep(1)
            
            # Check max messages limit
            if stats['success'] >= max_messages:
                print(f"✅ Reached max messages limit: {max_messages}")
                break
            
            # Skip if already sent
            if skip_sent and member['id'] in self.sent_users:
                stats['skipped'] += 1
                continue
            
            # Skip bots
            if member['is_bot']:
                stats['skipped'] += 1
                continue
            
            # Personalize message
            message = message_template.format(
                username=member['username'] or 'there',
                first_name=member['first_name'] or 'there',
                last_name=member['last_name'] or '',
                user_id=member['id']
            )
            
            try:
                # Send message
                user = await self.client.get_entity(member['id'])
                await self.client.send_message(user, message)
                
                stats['success'] += 1
                self.sent_users.add(member['id'])
                
                print(f"✅ Sent to @{member['username']} ({stats['success']}/{max_messages})")
                
                if progress_callback:
                    progress_callback(
                        f"Sent {stats['success']}/{max_messages} messages",
                        stats
                    )
                
            except FloodWaitError as e:
                print(f"⚠️ FLOOD WAIT: {e.seconds} seconds")
                stats['flood_wait'] += 1
                
                if progress_callback:
                    progress_callback(
                        f"Rate limited! Waiting {e.seconds} seconds...",
                        stats
                    )
                
                # Wait it out
                await asyncio.sleep(e.seconds)
                
                # Retry this user
                continue
                
            except UserPrivacyRestrictedError:
                print(f"⚠️ User {member['username']} has restricted privacy")
                stats['failed'] += 1
                
            except PeerFloodError:
                print("❌ PEER FLOOD ERROR - Your account is rate limited!")
                print("⚠️ Stop immediately and wait 24 hours")
                if progress_callback:
                    progress_callback("STOPPED: Account rate limited", stats)
                break
                
            except Exception as e:
                print(f"❌ Error sending to {member['username']}: {e}")
                stats['failed'] += 1
            
            # Delay before next message
            if randomize_delay:
                jitter = random.uniform(-0.3, 0.3)  # ±30%
                delay = delay_seconds * (1 + jitter)
            else:
                delay = delay_seconds
            
            print(f"⏳ Waiting {delay:.1f}s before next message...")
            await asyncio.sleep(delay)
        
        self.is_running = False
        
        print(f"\n✅ Mass DM Complete!")
        print(f"   Success: {stats['success']}")
        print(f"   Failed: {stats['failed']}")
        print(f"   Skipped: {stats['skipped']}")
        print(f"   Flood waits: {stats['flood_wait']}")
        
        return stats
    
    def pause(self):
        """Pause mass DM operation"""
        self.is_paused = True
        print("⏸️ Paused")
    
    def resume(self):
        """Resume mass DM operation"""
        self.is_paused = False
        print("▶️ Resumed")
    
    def stop(self):
        """Stop mass DM operation"""
        self.is_running = False
        print("⏹️ Stopped")
    
    def export_members_csv(self, filename="telegram_members.csv"):
        """Export scraped members to CSV"""
        if not self.members:
            print("❌ No members to export")
            return False
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.members[0].keys())
            writer.writeheader()
            writer.writerows(self.members)
        
        print(f"✅ Exported {len(self.members)} members to {filename}")
        return True
    
    def export_members_json(self, filename="telegram_members.json"):
        """Export scraped members to JSON"""
        if not self.members:
            print("❌ No members to export")
            return False
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.members, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Exported {len(self.members)} members to {filename}")
        return True


# Flask API Integration
import asyncio
from flask import Blueprint, request, jsonify, session

telegram_bp = Blueprint('telegram', __name__)

# Store scraper instances per session
scrapers = {}

@telegram_bp.route('/api/telegram/config', methods=['POST'])
def save_telegram_config():
    """Save Telegram API configuration"""
    data = request.json
    
    api_id = data.get('api_id')
    api_hash = data.get('api_hash')
    phone = data.get('phone')
    
    if not all([api_id, api_hash, phone]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Store in session
    session['telegram_api_id'] = api_id
    session['telegram_api_hash'] = api_hash
    session['telegram_phone'] = phone
    
    return jsonify({'success': True, 'message': 'Configuration saved'})

@telegram_bp.route('/api/telegram/auth', methods=['POST'])
async def test_telegram_auth():
    """Test Telegram authentication"""
    api_id = session.get('telegram_api_id')
    api_hash = session.get('telegram_api_hash')
    phone = session.get('telegram_phone')
    
    if not all([api_id, api_hash, phone]):
        return jsonify({'error': 'Configuration not set'}), 400
    
    try:
        scraper = TelegramScraper(api_id, api_hash, phone)
        await scraper.connect()
        
        # Store scraper instance
        scrapers[session.sid] = scraper
        
        return jsonify({'success': True, 'message': 'Authenticated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/api/telegram/scrape', methods=['POST'])
async def scrape_members_route():
    """Scrape members from a channel"""
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target channel required'}), 400
    
    scraper = scrapers.get(session.sid)
    if not scraper:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        members = await scraper.scrape_members(
            target,
            include_admins=data.get('include_admins', True),
            include_bots=data.get('include_bots', False),
            aggressive=data.get('aggressive', True)
        )
        
        return jsonify({
            'success': True,
            'members': members,
            'count': len(members)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/api/telegram/mass-dm', methods=['POST'])
async def mass_dm_route():
    """Start mass DM campaign"""
    data = request.json
    message = data.get('message')
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    scraper = scrapers.get(session.sid)
    if not scraper:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        stats = await scraper.send_mass_dm(
            message,
            delay_seconds=data.get('delay', 3),
            max_messages=data.get('max_messages', 50),
            randomize_delay=data.get('randomize_delay', True),
            skip_sent=data.get('skip_sent', True)
        )
        
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/api/telegram/export', methods=['POST'])
def export_members_route():
    """Export scraped members"""
    data = request.json
    format_type = data.get('format', 'csv')
    
    scraper = scrapers.get(session.sid)
    if not scraper:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        if format_type == 'csv':
            filename = f"telegram_members_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            scraper.export_members_csv(filename)
        else:
            filename = f"telegram_members_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            scraper.export_members_json(filename)
        
        return jsonify({
            'success': True,
            'filename': filename
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    """
    Command-line interface for testing
    """
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║  Telegram Member Scraper & Mass Messenger                         ║
║  For Authorized Security Research Only                            ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

⚠️  WARNING: This violates Telegram's ToS and may be illegal.
    Use ONLY with proper authorization for security research.
    Your account WILL be banned if you abuse this.

""")
    
    if len(sys.argv) < 4:
        print("Usage: python telegram_scraper.py <api_id> <api_hash> <phone>")
        print("\nGet API credentials from: https://my.telegram.org")
        sys.exit(1)
    
    api_id = sys.argv[1]
    api_hash = sys.argv[2]
    phone = sys.argv[3]
    
    async def main():
        scraper = TelegramScraper(api_id, api_hash, phone)
        await scraper.connect()
        
        # Interactive menu
        while True:
            print("\n" + "="*60)
            print("1. Scrape channel members")
            print("2. Send mass DM")
            print("3. Export members (CSV)")
            print("4. Export members (JSON)")
            print("5. Exit")
            print("="*60)
            
            choice = input("\nChoose option: ")
            
            if choice == '1':
                target = input("Enter channel (@username or link): ")
                members = await scraper.scrape_members(target)
                print(f"\n✅ Scraped {len(members)} members")
                
            elif choice == '2':
                if not scraper.members:
                    print("❌ No members loaded. Scrape first!")
                    continue
                
                print(f"\nLoaded: {len(scraper.members)} members")
                message = input("Enter message template: ")
                delay = int(input("Delay between messages (seconds): "))
                max_msg = int(input("Max messages to send: "))
                
                stats = await scraper.send_mass_dm(
                    message,
                    delay_seconds=delay,
                    max_messages=max_msg
                )
                
            elif choice == '3':
                scraper.export_members_csv()
                
            elif choice == '4':
                scraper.export_members_json()
                
            elif choice == '5':
                print("Goodbye!")
                break
    
    asyncio.run(main())
