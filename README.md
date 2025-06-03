# Grafana Data Source Secrets Extractor

## Description

This utility is a command-line tool designed to extract and decrypt sensitive information (such as passwords, API keys, and other secrets) stored in Grafana's SQLite database. It works with Grafana's built-in encryption mechanism to reveal the actual credentials used by data sources.

## Key Features

- Extracts encrypted secrets from Grafana's SQLite database (`grafana.db`)
- Decrypts sensitive fields stored in `secure_json_data` for each data source
- Supports Grafana's default encryption scheme (AES-CFB with PBKDF2 key derivation)
- Handles both the default and custom encryption secrets
- Displays decrypted credentials along with data source metadata (name, type, URL, etc.)

## Usage

```bash
go run extractor.go <grafana.db> <secret>
```

- `<grafana.db>` - Path to Grafana's SQLite database file (typically found in Grafana's data directory)
- `<secret>` - Grafana's secret key (default is `SW2YcwTIb9zpOOhoPsMm` if not changed)

## Output

For each data source, the tool displays:
- Data source name and type
- Connection URL
- User information (regular and basic auth)
- Each decrypted secret field (password, API key, etc.) with its corresponding key name

## Technical Details

The tool performs the following operations:
1. Reads the Grafana SQLite database
2. Extracts data source information from the `data_source` table
3. Retrieves encryption keys from the `data_keys` table
4. Decrypts the values using Grafana's encryption scheme:
   - AES-256 in CFB mode
   - PBKDF2 key derivation with SHA-256
   - 10,000 iterations for key stretching
   - 8-byte salt values

## Security Note

This tool should be used responsibly for legitimate purposes such as:
- Recovering lost credentials when migrating Grafana instances
- Auditing stored secrets for security compliance
- Troubleshooting data source connection issues

Always ensure proper authorization before accessing Grafana's database files, and handle decrypted credentials with care.

## Requirements

- Go runtime (to build from source)
- SQLite database file from a Grafana installation
- Knowledge of Grafana's secret key (or use default)
