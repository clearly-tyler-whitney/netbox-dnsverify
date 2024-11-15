# NetBox DNS Verify

NetBox DNS Verify is a tool designed to validate DNS records by comparing the records defined in [NetBox](https://netbox.readthedocs.io/en/stable/) with the actual records served by DNS servers. It helps ensure that your DNS infrastructure is consistent with your configuration management.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Environment Variables](#environment-variables)
  - [Configuration File](#configuration-file)
- [Examples](#examples)
- [Output Reports](#output-reports)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)

## Features

- Validates DNS records (A, AAAA, CNAME, NS, PTR, SOA) defined in NetBox against DNS servers.
- Supports SOA record validation with options to ignore serial numbers.
- Generates discrepancy reports in table, CSV, or JSON formats.
- Generates `nsupdate` scripts to correct discrepancies.
- Optionally records successful validations for audit purposes.
- Supports filtering by zones, views, and nameservers.
- Configurable via command-line flags, environment variables, and configuration files.
- Provides detailed logging with configurable log levels and formats.

## Installation

1. **Prerequisites**:
   - Go 1.23 or later
   - Access to a NetBox instance with the [NetBox DNS plugin](https://github.com/auroraresearchlab/netbox-dns)
   - DNS servers accessible from the machine running the tool

2. **Clone the Repository**:

   ```bash
   git clone https://github.com/clearly-tyler-whitney/netbox-dns-verify.git
   cd netbox-dns-verify
   ```

3. **Build the Application**:

   ```bash
   go build -o netbox-dnsverify
   ```

4. **Optional**: Move the binary to a directory in your `$PATH`:

   ```bash
   sudo mv netbox-dnsverify /usr/local/bin/
   ```

## Usage

```bash
netbox-dnsverify [options]
```

### Command-Line Options

| Option                               | Short | Description                                                                                          |
|--------------------------------------|-------|------------------------------------------------------------------------------------------------------|
| `--config`                           | `-c`  | Path to the configuration file (default: `./config.yaml`)                                            |
| `--api-url`                          | `-u`  | NetBox API root URL (e.g., `https://netbox.example.com/`)                                            |
| `--api-token`                        | `-t`  | NetBox API token                                                                                     |
| `--api-token-file`                   | `-T`  | Path to the NetBox API token file                                                                    |
| `--report-file`                      | `-r`  | File to write the discrepancy report (default: `discrepancies.txt`)                                  |
| `--report-format`                    | `-f`  | Format of the report (`table`, `csv`, `json`) (default: `table`)                                     |
| `--nsupdate-file`                    | `-n`  | File to write `nsupdate` commands (default: `nsupdate.txt`)                                          |
| `--ignore-serial-numbers`            | `-i`  | Ignore serial numbers when comparing SOA records                                                     |
| `--validate-soa`                     | `-s`  | SOA record validation (`false`, `true`, or `only`) (default: `false`)                                |
| `--log-level`                        | `-l`  | Log level (`debug`, `info`, `warn`, `error`) (default: `info`)                                       |
| `--log-format`                       | `-L`  | Log format (`logfmt` or `json`) (default: `logfmt`)                                                  |
| `--zone`                             | `-z`  | Filter by zone name                                                                      |
| `--view`                             | `-v`  | Filter by view name                                                                      |
| `--nameserver`                       | `-N`  | Filter by nameserver                                                                     |
| `--record-successful`                | `-R`  | Record successful validations                                                                        |
| `--successful-report-file`           | `-S`  | File to write successful validations report (default: `successful_validations.json`)                 |
| `--help`                             | `-h`  | Display help message                                                                                 |

### Environment Variables

Environment variables can be used to set options. They are prefixed with `DNSVERIFY_` and correspond to the command-line flags. For example:

- `DNSVERIFY_API_URL`
- `DNSVERIFY_API_TOKEN`

### Configuration File

You can also use a YAML configuration file to set options. By default, the tool looks for `config.yaml` in the current directory or `/etc/netbox-dnsverify/`. You can specify a different configuration file using the `--config` flag.

Example `config.yaml`:

```yaml
api_url: https://netbox.example.com/
api_token: your_api_token
report_file: discrepancies.json
report_format: json
validate_soa: true
ignore_serial_numbers: true
log_level: info
log_format: json
record_successful: true
successful_report_file: successful_validations.json
```

## Examples

1. **Validate DNS Records Using Config File**:

   ```bash
   netbox-dnsverify -c /path/to/config.yaml
   ```

2. **Validate DNS Records with Command-Line Options**:

   ```bash
   netbox-dnsverify \
     -u https://netbox.example.com/ \
     -t your_api_token \
     -d dns1.example.com,dns2.example.com \
     -r discrepancies.csv \
     -f csv \
     -s true \
     -i \
     -l debug \
     -R \
     -S success.json
   ```

3. **Validate Only SOA Records**:

   ```bash
   netbox-dnsverify -u https://netbox.example.com/ -t your_api_token -s only
   ```

4. **Filter by Zone and View**:

   ```bash
   netbox-dnsverify -u https://netbox.example.com/ -t your_api_token -z example.com -v internal
   ```

5. **Use Environment Variables**:

   ```bash
   export DNSVERIFY_API_URL="https://netbox.example.com/"
   export DNSVERIFY_API_TOKEN="your_api_token"
   export DNSVERIFY_DNS_SERVERS="dns1.example.com,dns2.example.com"
   netbox-dnsverify
   ```

## Output Reports

### Discrepancy Report

The discrepancy report lists all DNS records that do not match between NetBox and the DNS servers. The report can be generated in three formats:

- **Table**: A human-readable text format (default).
- **CSV**: Comma-separated values, suitable for spreadsheets.
- **JSON**: Machine-readable JSON format.

Example discrepancy in JSON format:

```json
[
  {
    "FQDN": "test.example.com.",
    "RecordType": "A",
    "Expected": ["192.0.2.1"],
    "Actual": ["192.0.2.2"],
    "Server": "dns1.example.com",
    "Message": "Record values mismatch"
  }
]
```

### Successful Validations Report

If `--record-successful` is enabled, the tool generates a report of all successful validations.

Example successful validation in JSON format:

```json
[
  {
    "FQDN": "www.example.com.",
    "RecordType": "A",
    "Expected": ["192.0.2.10"],
    "Actual": ["192.0.2.10"],
    "Server": "dns1.example.com",
    "Message": "Record validated successfully"
  }
]
```

### NSUpdate Script

An `nsupdate` script is generated to help correct discrepancies. The script includes DNS update commands that can be applied to synchronize DNS servers with NetBox.

Example `nsupdate.txt`:

```
server dns1.example.com
zone example.com
update delete test.example.com. A
update add test.example.com. 3600 A 192.0.2.1
send
```

## Logging

The tool provides detailed logging with configurable levels and formats.

- **Log Levels**:
  - `debug`: Detailed debug information.
  - `info`: General operational information.
  - `warn`: Warnings about potential issues.
  - `error`: Errors that prevent operations from completing.

- **Log Formats**:
  - `logfmt`: Key-value pairs (default).
  - `json`: JSON-formatted logs.

Set the log level and format using `--log-level` and `--log-format` flags or corresponding environment variables.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Write tests for any new functionality.
4. Submit a pull request with a detailed description of your changes.

Please ensure your code adheres to the existing style and includes appropriate documentation.

## License

This project is licensed under the [MIT License](LICENSE).

---

*Disclaimer: This tool is not affiliated with or endorsed by the official NetBox project. Use it at your own risk.*