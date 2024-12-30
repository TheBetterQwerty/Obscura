# Password Manager

This Go-based password manager provides secure storage, management, and encryption of passwords. It supports various features like adding new passwords, viewing saved passwords, editing, deleting, importing/exporting passwords, and generating random passwords. All passwords are encrypted and stored in binary files for safety.

## Features

- **Store and Manage Passwords**: Add, edit, or delete password entries securely.
- **Encryption**: Passwords are encrypted using a hash-based encryption method.
- **Export and Import**: Import passwords from a CSV file and export them to a CSV.
- **Generate Random Passwords**: Generate secure random passwords of 20 characters.
- **View Saved Passwords**: View encrypted passwords (decrypted with the master password).
- **Database Creation**: Initialize the password manager with a master password for the database.
  
## Setup Instructions

1. Clone or download the repository.
2. Install Go (version 1.18 or above) if not already installed.
3. Navigate to the project directory and run the following commands to install dependencies and build the program.

    ```bash
    go mod init password-manager
    go run main.go
    ```

4. If this is your first time running the program, you will be prompted to create a master password to secure your password database.

## Usage

### Initial Setup

1. On the first run, the program will ask you to create a master password. This password will protect the password database.
2. After creating the master password, the database will be initialized, and the password manager will be ready for use.

### Main Menu

Once logged in with your master password, you will see the following options in the menu:

1. **View Saved Passwords**: View all saved passwords (after decrypting them with the master password).
2. **Add New Password**: Add a new password entry (with site, username, password, and optional note).
3. **Generate Password**: Generate a random secure password.
4. **Delete Password**: Delete an existing password entry by searching for the site or username.
5. **Edit Existing Password**: Edit an existing password entry by searching for the site or username.
6. **Import Password From File**: Import passwords from a CSV file.
7. **Export Passwords**: Export all passwords to a CSV file.
8. **Exit Password Manager**: Exit the application.

### Example Operations

#### Add New Password
To add a new password, you will be asked for:
- **Site**: Name of the site/service.
- **Username**: Username associated with the site.
- **Password**: Password (Leave blank to generate a random password).
- **Note**: Optional notes for the password.

#### View Saved Passwords
You can view all your stored passwords, with each password's site, username, and note (encrypted and decrypted using your master password).

#### Generate Random Password
If you need a random password, simply choose the "Generate Password" option. A new password of 20 characters will be generated.

#### Import and Export
You can import passwords from a CSV file or export all saved passwords to a CSV file. When importing, the passwords are encrypted using your master password.

#### Edit or Delete Password
You can search for passwords by site name or username and make changes or remove them entirely.

### Encryption and Security

- Passwords are stored securely using encryption techniques.
- All password data is encrypted before being written to disk.
- The program uses a hashed master password to protect the database. Your passwords are decrypted only when you provide the correct master password.

## File Structure

- `pass/`: Directory where password data and database files are stored.
  - `pass/dump.bin`: Stores the hashed master password.
  - `pass/pass.bin`: Stores encrypted password entries.
- `datadump.csv`: Exported file where passwords can be saved in CSV format.
  
## Dependencies

- `mymodule`: A custom module for encryption and hashing.
  
Ensure that the custom `mymodule` is available and contains the necessary functions for encrypting, decrypting, and hashing passwords (`Encrypt`, `Decrypt`, `Hash256`, `Hash512`).

## Example Commands

- **Create Database Password**: Prompts the user to create a password to protect the database.
- **Import CSV**: Imports passwords from a CSV file.
- **Export to CSV**: Exports all saved passwords into a CSV file.

## Error Handling

- If an error occurs while loading or saving passwords, an error message is logged.
- If the user attempts to enter an incorrect password multiple times, they are prompted again, with a limited number of attempts.

---

**Created by**: Qwerty  
**Date**: 12/30/2024
