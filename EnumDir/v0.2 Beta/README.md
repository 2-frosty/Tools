# EnumDir

Subdomain, directory, file and CMS enumeration tool for authorised security testing.

## Install

```bash
pip install -r requirements.txt
```

Required: `requests`, `dnspython`, `rich`

## Usage

```bash
python EnumDir.py <target> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--subdomains` | Run subdomain enumeration (DNS bruteforce + crt.sh) |
| `--dirs` | Run directory/file enumeration |
| `--cms` | Run CMS/technology fingerprinting |
| `--wordlist PATH` | Custom wordlist (default: `wordlists/subdomains.txt` / `wordlists/directories.txt`) |
| `--extensions EXT [EXT ...]` | File extensions to probe. Use `all` for `php html htm aspx bak` |
| `--threads N` | Number of threads (default: 20) |
| `--https` | Use HTTPS instead of HTTP |
| `--timeout SEC` | Request timeout in seconds (default: 5) |
| `--status-codes CODE [CODE ...]` | Only show these HTTP status codes |
| `--hide-status-codes CODE [CODE ...]` | Hide these codes (default: 404) |
| `--output-json FILE` | Save results as JSON |
| `--output-txt FILE` | Save results as plain text |
| `--quiet` | Suppress per-result output (summary only) |

### Examples

```bash
# Full scan
python EnumDir.py example.com --subdomains --dirs --cms

# Subdomains only
python EnumDir.py example.com --subdomains

# Directory enumeration with PHP extension probing
python EnumDir.py example.com --dirs --extensions php txt

# Quiet mode with JSON output
python EnumDir.py example.com --dirs --cms --quiet --output-json results.json

# Show only 200 and 403 responses
python EnumDir.py example.com --dirs --status-codes 200 403
```

## Wordlists

Default wordlists expected at:
- `wordlists/subdomains.txt`
- `wordlists/directories.txt`

## Modules

- **subdomains** — crt.sh certificate transparency + DNS bruteforce
- **directories** — threaded HTTP directory/file enumeration
- **cms** — technology fingerprinting (WordPress, Joomla, Drupal, Magento, Shopify, Next.js, and more)
- **reporter** — JSON and plain text export