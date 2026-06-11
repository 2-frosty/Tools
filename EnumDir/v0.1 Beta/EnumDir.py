#!/usr/bin/env python3

import argparse
import json
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from modules.subdomains import bruteforce, crt_sh
from modules.directories import enumerate_dirs
from modules.reporter import save_json, save_txt

console = Console()

BANNER = """
[bold red]
 ▄▄▄▄ ▄▄▄▄  ▄▄▄▄ ▄▄   ▄▄▄▄  ▄▄▄ 
░█ ▀▀ ░█ ░█ ░█ ░█ ░█ ░█ ░█ ░█ ░█
 ▀▀░▄ ▒█ ░█ ▒█ ▒█ ▒█ ▒█ ░█ ▒█ ░█
░█ ▓░ ▓▓ ▓░ ▓▓ ▓▓ ▓▓ ▓▓ ▓░ ▓▓ ▓░
▀▀▀▀  ▀▀ ▀▀ ▀▀ ▀▀ ▀▀  ▀▀▀▀ ▒█▀▀ 
                           ▀▀   
[/bold red]
[dim]Subdomain · Directory · File Enumeration Tool[/dim]
[dim]For authorised testing only.[/dim]
"""

def print_summary_table(results):
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("Type", style="bold white")
    table.add_column("Count", justify="right", style="bold green")

    if "subdomains" in results:
        table.add_row("Subdomains found", str(len(results["subdomains"])))
    if "directories" in results:
        dirs = [r for r in results["directories"] if "." not in r["url"].split("/")[-1]]
        files = [r for r in results["directories"] if "." in r["url"].split("/")[-1]]
        table.add_row("Directories found", str(len(dirs)))
        table.add_row("Files found", str(len(files)))

    console.print(table)

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="Recon Tool — Subdomain, Directory & File Enumeration",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target domain, e.g. example.com")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--dirs", action="store_true", help="Run directory/file enumeration")
    parser.add_argument(
        "--sub-wordlist",
        default="wordlists/subdomains.txt",
        help="Wordlist for subdomain bruteforce (default: wordlists/subdomains.txt)"
    )
    parser.add_argument(
        "--dir-wordlist",
        default="wordlists/directories.txt",
        help="Wordlist for directory/file bruteforce (default: wordlists/directories.txt)"
    )
    parser.add_argument(
    "--extensions",
    nargs="+",
    default=[],
    metavar="EXT",
    help="File extensions to probe e.g. --extensions php txt bak (default: none)"
    )
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--output-json", metavar="FILE", help="Save results to a JSON file")
    parser.add_argument("--output-txt", metavar="FILE", help="Save results to a plain text file")
    parser.add_argument(
        "--status-codes",
        nargs="+",
        type=int,
        default=[200, 301, 302, 403],
        metavar="CODE",
        help="HTTP status codes to flag (default: 200 301 302 403)"
    )

    args = parser.parse_args()

    if not args.subdomains and not args.dirs:
        console.print("[bold yellow][!] No modules selected. Use --subdomains, --dirs, or both.[/bold yellow]")
        parser.print_help()
        sys.exit(1)

    results = {}
    protocol = "https" if args.https else "http"

    # --- Subdomain Enumeration ---
    if args.subdomains:
        console.print(Panel("[bold cyan][*] Starting subdomain enumeration...[/bold cyan]", expand=False))

        ct_results = []
        try:
            console.print("[*] Querying certificate transparency logs (crt.sh)...")
            ct_results = crt_sh(args.target)
            console.print(f"[green][+] crt.sh returned {len(ct_results)} entries[/green]")
        except Exception as e:
            console.print(f"[yellow][!] crt.sh query failed: {e}[/yellow]")

        dns_results = []
        try:
            console.print(f"[*] Bruteforcing subdomains with wordlist: {args.sub_wordlist}")
            dns_results = bruteforce(args.target, args.sub_wordlist, args.threads)
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist not found: {args.sub_wordlist}[/red]")

        combined = sorted(set(ct_results + dns_results))
        results["subdomains"] = combined

        if combined:
            console.print(f"\n[bold green][+] {len(combined)} unique subdomains found:[/bold green]")
            for sub in combined:
                console.print(f"  [green]→[/green] {sub}")
        else:
            console.print("[yellow][!] No subdomains found.[/yellow]")

    # --- Directory & File Enumeration ---
    if args.dirs:
        console.print(Panel("[bold cyan][*] Starting directory and file enumeration...[/bold cyan]", expand=False))
        base_url = f"{protocol}://{args.target}"

        try:
            dir_results = enumerate_dirs(
                base_url=base_url,
                wordlist_path=args.dir_wordlist,
                extensions=args.extensions,
                threads=args.threads,
                timeout=args.timeout,
                valid_codes=args.status_codes
            )
            results["directories"] = dir_results
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist not found: {args.dir_wordlist}[/red]")
            results["directories"] = []

    # --- Summary ---
    console.print(Panel("[bold white]Scan Summary[/bold white]", expand=False))
    print_summary_table(results)

    # --- Output ---
    if args.output_json:
        save_json(results, args.output_json)
        console.print(f"[bold green][+] JSON results saved to {args.output_json}[/bold green]")

    if args.output_txt:
        save_txt(results, args.output_txt)
        console.print(f"[bold green][+] Text results saved to {args.output_txt}[/bold green]")

if __name__ == "__main__":
    main()
