# EnumDir

Subdomain, directory, file and CMS enumeration tool for authorised security testing.
This has been created as part of my preparation for the CPTS/OSCP exams, and should always be used only on domains in which you own or have permission to scan.
As a developer, I believe in free, open source software, so feel free to make any changes you like.
If you have any feedback, please contact me at 2fr0sty@proton.me .

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

You must specify the full path to your wordlist of choice with the `--wordlist` flag. 
I recommend using wordlists from `seclists`, which is pre-installed on Kali Linux/Parrot OS.

## Modules

- **subdomains** — crt.sh certificate transparency + DNS bruteforce
- **directories** — threaded HTTP directory/file enumeration
- **cms** — technology fingerprinting (WordPress, Joomla, Drupal, Magento, Shopify, Next.js, and more)
- **reporter** — JSON and plain text export
