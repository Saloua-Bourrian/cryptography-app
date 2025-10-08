#!/usr/bin/env python3
"""
Minimal text-based user system for an encrypted-diary project (phase 1).
- Registers users (stores username & PASSWORD IN CLEARTEXT per assignment spec).
- Authenticates users by comparing the provided password to stored one.
NOTE: This is intentionally insecure. Do not use in production.
"""
import json
import os
from getpass import getpass

DB_FILE = "users_db.json"


def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def register_user(db):
    print("\n=== Register User ===")
    username = input("Choose a username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return db

    if username in db:
        print("That username is already taken.")
        return db

    # Per assignment: store password in CLEARTEXT
    password = getpass("Choose a password (will be stored in CLEARTEXT): ").strip()
    if not password:
        print("Password cannot be empty.")
        return db

    db[username] = {
        "password": password  # CLEARTEXT on purpose for minimal prototype
    }
    save_db(db)
    print(f"User '{username}' registered.\n")
    return db


def authenticate_user(db):
    print("\n=== Login ===")
    username = input("Username: ").strip()
    if username not in db:
        print("No such user.")
        return False

    password = getpass("Password: ").strip()

    # Minimal check per assignment: equality with stored CLEARTEXT password
    if password == db[username]["password"]:
        print("Login successful!")
        return True
    else:
        print("Incorrect password.")
        return False


def main():
    db = load_db()
    while True:
        print("\n=== Minimal User System ===")
        print("1) Register")
        print("2) Login")
        print("3) Exit")
        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            db = load_db()  # reload in case file changed
            db = register_user(db)
        elif choice == "2":
            db = load_db()
            authenticate_user(db)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")


if __name__ == "__main__":
    main()
