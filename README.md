# Firefox_Decrypt_ASN.1-Delphi

A Delphi-based utility for recovering stored passwords from Firefox profiles. This tool can decrypt passwords stored in Firefox's password manager using the browser's built-in encryption mechanisms.

## ⚠️ Security Notice

This tool is intended for **legitimate password recovery purposes only**, such as:
- Recovering your own forgotten passwords
- Data migration between browsers
- Personal security auditing

Please ensure you have the legal right to access any passwords you attempt to decrypt.

## 🌟 Features

- Supports multiple Firefox profiles
- Handles newer Firefox encryption schemes
- Multiple output formats:
  - Human-readable text
  - JSON
  - CSV
- Automatic profile detection

## 🏗️ Technical Details

The tool implements Firefox's password encryption scheme, including:
- ASN.1 structure parsing
- 3DES and AES-256 decryption
- PBKDF2 key derivation
- NSS (Network Security Services) master key extraction
- Support for key4.db databases

## 🔧 Prerequisites

- Windows operating system
- Firefox profile with saved passwords
- Delphi development environment (if building from source)
- sqlite DLL (include)
- Required Delphi components:
  - UniDAC (for SQLite database access)
  - DEC (Delphi Encryption Components)

## 🚀 Usage

```bash
FirefoxDecrypt.exe [options]

Options:
  -f, --format FORMAT   Output format (human, json, csv)
  -l, --list           List available profiles
  -c, --choice NUMBER  Profile to use (starts with 1)
  -h, --help          Show this help message
```

### Examples

List available profiles:
```bash
FirefoxDecrypt.exe --list
```

Decrypt passwords from specific profile:
```bash
FirefoxDecrypt.exe --choice 1
```

Export as JSON:
```bash
FirefoxDecrypt.exe --format json
```

## How it Works

1. Locates Firefox profiles on the system
2. Extracts the master key from key4.db
3. Reads encrypted passwords from logins.json
4. Decrypts individual entries using:
   - Global salt from key4.db
   - Master key derived from metadata
   - Individual encryption keys for each entry

## 📄 License

This project is intended for educational and recovery purposes only. Please ensure compliance with applicable laws and regulations in your jurisdiction.

## ⚠️ Disclaimer

This tool comes with no warranties or guarantees. Users are responsible for ensuring they have the legal right to access any passwords they attempt to decrypt.

<p align="center">Made with ❤️ using Delphi RAD Studio</p>