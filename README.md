# Password Authentication System

A secure user management system implementing bcrypt password hashing with forced password change functionality.

## Features

- Secure password storage using bcrypt hashing
- User management operations:
  - Add new users
  - Change passwords
  - Force password change on next login
  - Remove users
- Login system with:
  - 3-attempt limit
  - Forced password change capability
  - Secure password confirmation

## Files

- `login.py` - Handles user authentication
- `usermgmt.py` - User management utility
- `user.txt` - User credential storage (auto-created)

## Installation

1. Ensure Python 3.x is installed
2. Install required dependencies:
`pip install bcrypt`

## Usage

### User Management
`python usermgmt.py <command> <username>`

Available commands:
- `add` - Add a new user
- `passwd` - Change user password
- `forcepass` - Force password change on next login
- `del` - Remove a user

### User Login
`python login.py <username>`

## Security Features

- All passwords are hashed with bcrypt (salt + stretching)
- Usernames are hashed before storage
- Password confirmation required for changes
- Forced password change functionality
- Login attempt limiting

## Data Storage

User credentials are stored in `user.txt` with the format:
`hashed_username:::hashed_password:::force_change_flag`

## Notes

- The system automatically creates `user.txt` if it doesn't exist
- All passwords are hidden during input
- Password changes require confirmation
- Forced password changes take effect on next login

## Requirements

- Python 3.x
- bcrypt library
