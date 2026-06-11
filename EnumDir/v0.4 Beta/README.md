#  ▄▄▄▄ ▄▄▄▄  ▄▄▄▄ ▄▄   ▄▄▄▄  ▄▄▄ 
# ░█ ▀▀ ░█ ░█ ░█ ░█ ░█ ░█ ░█ ░█ ░█
# ▀▀░▄ ▒█ ░█ ▒█ ▒█ ▒█ ▒█ ░█ ▒█ ░█
# ░█ ▓░ ▓▓ ▓░ ▓▓ ▓▓ ▓▓ ▓▓ ▓░ ▓▓ ▓░
# ▀▀▀▀  ▀▀ ▀▀ ▀▀ ▀▀ ▀▀  ▀▀▀▀ ▒█▀▀ 
#                            ▀▀   

A Python-based web reconnaissance tool for subdomain enumeration, directory bruteforcing, and file discovery. Built for use during authorised penetration tests and bug bounty engagements.

---

## ⚠️ Legal Disclaimer

This tool is designed for people performing penetration testing exercises, on machines they are **AUTHORISED TO SCAN**, including real environments with the clients permission, and lab environments such as HackTheBox, TryHackMe, etc...
If you ignore this message anyway, I will not take responsibility for your actions.

---

## Features

- **Subdomain enumeration** via DNS bruteforce and certificate transparency logs (crt.sh — passive, no requests to the target)
- **Directory bruteforce** with configurable wordlists
- **File discovery** across configurable extensions (`.php`, `.bak`, `.env`, `.js` etc.)
- Colour-coded terminal output with status codes
- JSON and plain text report output
- Multithreaded for speed
- Reusable session with connection pooling

---

## Installation

```bash
git clone https://github.com/yourusername/recon-tool.git
cd recon-tool
pip install -r requirements.txt
```

---

## Wordlists

I've added two wordlists currently, `directories.txt` and `subdomains.txt`. To add your own wordlists, just specify the file path and add them to this directory.

---

## Usage

### Subdomain enumeration only
```bash
python main.py example.com --subdomains
```

### Directory and file enumeration only
```bash
python main.py example.com --dirs
```

### Full recon (both modules)
```bash
python main.py example.com --subdomains --dirs
```

### Custom wordlists and extensions
```bash
python main.py example.com --dirs \
  --dir-wordlist wordlists/common.txt \
  --extensions php txt js bak env old zip
```

### HTTPS target with output
```bash
python main.py example.com --subdomains --dirs --https \
  --output-json results.json \
  --output-txt results.txt
```

### All options
```
positional arguments:
  target                Target domain, e.g. example.com

options:
  --subdomains          Run subdomain enumeration
  --dirs                Run directory/file enumeration
  --sub-wordlist FILE   Wordlist for subdomain bruteforce
  --dir-wordlist FILE   Wordlist for directory/file bruteforce
  --extensions EXT+     File extensions to probe
  --threads N           Number of threads (default: 20)
  --https               Use HTTPS instead of HTTP
  --timeout N           Request timeout in seconds (default: 5)
  --output-json FILE    Save results to a JSON file
  --output-txt FILE     Save results to a plain text file
  --status-codes CODE+  HTTP status codes to flag (default: 200 301 302 403)
```