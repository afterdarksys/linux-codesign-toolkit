#!/usr/bin/env python3
"""
Script to create an admin user for the Code Signing API.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import asyncio
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from codesign_api.database import create_tables, AsyncSessionLocal
from codesign_api.auth import create_api_user, generate_api_key

async def create_admin():
    """Create an admin user."""
    print("Linux Code Signing Toolkit API - Admin User Creation")
    print("=" * 60)

    # Get user details
    user_id = input("Enter admin user ID: ").strip()
    if not user_id:
        print("Error: User ID is required")
        return

    name = input("Enter admin name (optional): ").strip() or None
    email = input("Enter admin email (optional): ").strip() or None

    # Generate API key
    api_key = generate_api_key()

    try:
        # Create database tables if they don't exist
        await create_tables()

        # Create user
        async with AsyncSessionLocal() as db:
            user = await create_api_user(
                db=db,
                user_id=user_id,
                api_key=api_key,
                name=name,
                email=email,
                allowed_signing_types="windows,java,air,apple",
                max_operations_per_day=10000  # Higher limit for admin
            )

        print("\n" + "=" * 60)
        print("Admin user created successfully!")
        print("=" * 60)
        print(f"User ID: {user.user_id}")
        print(f"API Key: {api_key}")
        print(f"Name: {user.name or 'N/A'}")
        print(f"Email: {user.email or 'N/A'}")
        print(f"Created: {user.created_at}")
        print("=" * 60)
        print("\nIMPORTANT: Save the API key securely - it cannot be retrieved again!")
        print("You can use this API key in the X-API-Key header for API requests.")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    asyncio.run(create_admin())