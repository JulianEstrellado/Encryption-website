# Encryption-website

A simple secure file sharing system built with Node.js and Express.

## Features

- User registration and login
- Per-user ownership and shared access control
- Upload files securely with password-based encryption
- AES-256-GCM encryption for confidentiality and integrity
- Download only for authorized users

## Setup

1. Install dependencies:

```bash
npm install
```

2. Start the server:

```bash
npm start
```

3. Open the app in your browser:

```bash
http://localhost:3000
```

## Usage

- Register a new account or login if you already have one
- Upload a file and optionally share it with other registered usernames
- The file is encrypted on upload with a password
- Authorized users can open the download link, enter the same password, and decrypt the file

## Encryption details

This app uses a simple but secure encryption pattern:

- Passwords are hashed with `bcryptjs` before storage
- File decryption passwords are never stored in plaintext
- For each uploaded file, the server derives a 256-bit key from the password using PBKDF2
- The file is encrypted with AES-256-GCM
- The encrypted file stores the salt, IV, auth tag, and ciphertext together

## Notes

- This is a demo implementation. For production use, add HTTPS, stronger session secrets, persistent databases, file expiration cleanup, and better input validation.
- The encryption technique is intentionally simple, but it uses strong primitives provided by Node.js.


A simple secure file sharing system built with Node.js and Express.

## Features

- Upload files securely with password-based encryption
- AES-256-GCM encryption for confidentiality and integrity
- Download files only after entering the correct password
- Simple single-page web interface

## Setup

1. Install dependencies:

```bash
npm install
```

2. Start the server:

```bash
npm start
```

3. Open the app in your browser:

```bash
http://localhost:3000
```

## Usage

- Choose a file and enter a strong password to upload
- The server encrypts the file before storing it
- Copy the returned download link and share it with the recipient
- The recipient uses the link and the same password to download the file

## Notes

- Passwords are never stored in plaintext
- Files are stored encrypted on disk in `uploads/`
- This is a simple demo; for production use, add HTTPS, stronger storage controls, expiration cleanup, and authentication
