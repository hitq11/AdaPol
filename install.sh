#!/bin/bash

# AdaPol Installation Script
set -e

echo "🚀 Installing AdaPol: Adaptive Multi-Cloud Least-Privilege Policy Generator"
echo "========================================================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1-2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8+ required. Found: $python_version"
    exit 1
fi

echo "✅ Python $python_version detected"

# Create virtual environment
echo "🐍 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📋 Installing dependencies..."
pip install -r requirements.txt

# Install in development mode
echo "🔧 Installing AdaPol..."
pip install -e .

echo "✅ Installation complete!"
echo ""
echo "🎯 Quick start:"
echo "  source venv/bin/activate"
echo "  adapol --demo"
echo ""
echo "📚 For more information:"
echo "  adapol --help"
echo "  cat README.md"
echo ""
echo "🚀 Happy policy optimization!"
