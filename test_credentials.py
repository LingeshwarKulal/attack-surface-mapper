"""
Quick test script to verify your API credentials are working.
"""

import os
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

print("="*70)
print("API CREDENTIALS TEST")
print("="*70)

# Check if credentials are loaded
google_api_key = os.getenv('GOOGLE_API_KEY')
google_cse_id = os.getenv('GOOGLE_CSE_ID')
github_token = os.getenv('GITHUB_TOKEN')

print("\n📋 Checking credentials...")
print(f"   Google API Key: {'✅ Found' if google_api_key else '❌ Missing'}")
print(f"   Google CSE ID: {'✅ Found' if google_cse_id else '❌ Missing'}")
print(f"   GitHub Token: {'✅ Found' if github_token else '❌ Missing'}")

# Test GitHub API
print("\n🔍 Testing GitHub API...")
if github_token:
    try:
        headers = {'Authorization': f'token {github_token}'}
        response = requests.get('https://api.github.com/user', headers=headers, timeout=10)
        if response.status_code == 200:
            user_data = response.json()
            print(f"   ✅ GitHub API working!")
            print(f"   📊 Rate limit: {response.headers.get('X-RateLimit-Remaining')}/{response.headers.get('X-RateLimit-Limit')}")
            if 'login' in user_data:
                print(f"   👤 Authenticated as: {user_data['login']}")
        else:
            print(f"   ❌ GitHub API failed: {response.status_code}")
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
else:
    print("   ⚠️  Skipped (no token)")

# Test Google API
print("\n🔍 Testing Google Custom Search API...")
if google_api_key and google_cse_id and google_cse_id != 'your_custom_search_engine_id_here':
    try:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            'key': google_api_key,
            'cx': google_cse_id,
            'q': 'test',
            'num': 1
        }
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Google API working!")
            print(f"   📊 Search returned {len(data.get('items', []))} result(s)")
        else:
            print(f"   ❌ Google API failed: {response.status_code}")
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
elif not google_api_key:
    print("   ⚠️  Skipped (no API key)")
elif google_cse_id == 'your_custom_search_engine_id_here':
    print("   ⚠️  Google CSE ID not configured yet")
    print("   📝 Create one at: https://programmablesearchengine.google.com/")
else:
    print("   ⚠️  Skipped (CSE ID missing)")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)

ready = True
if not github_token:
    print("❌ GitHub token not configured")
    ready = False
if not google_api_key:
    print("❌ Google API key not configured")
    ready = False
if not google_cse_id or google_cse_id == 'your_custom_search_engine_id_here':
    print("⚠️  Google CSE ID not configured")
    print("   Create one at: https://programmablesearchengine.google.com/")
    ready = False

if ready:
    print("✅ All credentials configured and working!")
    print("\n🚀 You can now run the tool:")
    print("   python src/main.py --target example.com")
else:
    print("\n📝 Please complete the configuration:")
    print("   1. Create Google CSE at: https://programmablesearchengine.google.com/")
    print("   2. Copy the CSE ID")
    print("   3. Edit .env file and replace 'your_custom_search_engine_id_here'")
    print("   4. Run this test again: python test_credentials.py")

print()
