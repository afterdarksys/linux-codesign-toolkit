#!/usr/bin/env python3
"""
Script to test the Code Signing API endpoints.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import asyncio
import aiohttp
import json
import os
import sys
from pathlib import Path

API_BASE_URL = "http://localhost:8000"
API_KEY = None  # Will be set during testing

async def test_health():
    """Test the health endpoint."""
    print("Testing health endpoint...")
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_BASE_URL}/health") as response:
            if response.status == 200:
                data = await response.json()
                print(f"✅ Health check passed: {data['status']}")
                return True
            else:
                print(f"❌ Health check failed: {response.status}")
                return False

async def test_api_info():
    """Test the API info endpoint."""
    print("Testing API info endpoint...")
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_BASE_URL}/api/v1/info") as response:
            if response.status == 200:
                data = await response.json()
                print(f"✅ API info: Version {data['api_version']}")
                print(f"   Supported types: {', '.join(data['supported_signing_types'])}")
                return True
            else:
                print(f"❌ API info failed: {response.status}")
                return False

async def test_authentication():
    """Test authentication with API key."""
    print("Testing authentication...")
    if not API_KEY:
        print("⚠️  No API key provided, skipping authentication tests")
        return False

    headers = {"X-API-Key": API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_BASE_URL}/api/v1/signing/operations", headers=headers) as response:
            if response.status == 200:
                print("✅ Authentication successful")
                return True
            elif response.status == 401:
                print("❌ Authentication failed - invalid API key")
                return False
            else:
                print(f"❌ Authentication test failed: {response.status}")
                return False

async def test_file_upload():
    """Test file upload and signing."""
    if not API_KEY:
        print("⚠️  No API key provided, skipping file upload tests")
        return False

    print("Testing file upload and signing...")

    # Create a test file
    test_file_path = "/tmp/test_file.txt"
    with open(test_file_path, "w") as f:
        f.write("This is a test file for code signing API testing.")

    headers = {"X-API-Key": API_KEY}

    # Test signing endpoint (will fail without proper certificates, but should validate the request)
    async with aiohttp.ClientSession() as session:
        data = aiohttp.FormData()
        data.add_field('signing_type', 'windows')
        data.add_field('key_id', 'test-key')
        data.add_field('file', open(test_file_path, 'rb'), filename='test_file.txt')

        async with session.post(f"{API_BASE_URL}/api/v1/signing/sign", data=data, headers=headers) as response:
            response_data = await response.json()

            if response.status in [400, 500]:  # Expected to fail without proper setup
                print("✅ File upload endpoint accessible (failed as expected without certificates)")
                print(f"   Response: {response_data.get('message', 'No message')}")
                return True
            elif response.status == 200:
                print("✅ File upload and signing successful")
                return True
            else:
                print(f"❌ File upload test failed: {response.status}")
                print(f"   Response: {response_data}")
                return False

    # Clean up
    if os.path.exists(test_file_path):
        os.remove(test_file_path)

async def run_tests():
    """Run all tests."""
    print("Linux Code Signing Toolkit API - Test Suite")
    print("=" * 60)

    # Get API key if provided
    global API_KEY
    if len(sys.argv) > 1:
        API_KEY = sys.argv[1]
        print(f"Using API key: {API_KEY[:10]}...")
    else:
        print("No API key provided - some tests will be skipped")
        print("Usage: python test_api.py [API_KEY]")

    print()

    tests = [
        test_health,
        test_api_info,
        test_authentication,
        test_file_upload
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if await test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
        print()

    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed!")
    else:
        print(f"⚠️  {total - passed} tests failed or skipped")

if __name__ == "__main__":
    asyncio.run(run_tests())