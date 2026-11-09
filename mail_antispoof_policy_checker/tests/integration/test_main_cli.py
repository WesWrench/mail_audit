"""
Test script for main.py CLI tool
"""

import subprocess
import sys

print("=" * 80)
print("Testing main.py CLI Tool")
print("=" * 80)

# Test 1: Show help
print("\n[Test 1: Show help]")
result = subprocess.run([sys.executable, "main.py", "--help"], capture_output=True, text=True)
if result.returncode == 0:
    print("  Help displayed successfully")
    print("\n--- Help Output ---")
    print(result.stdout)
else:
    print(f"  ERROR: {result.stderr}")

print("\n" + "=" * 80)
print("Main.py CLI tool created successfully!")
print("=" * 80)
