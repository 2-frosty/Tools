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
from modules.cms import fingerprint_cms
from modules.reporter import save_json, save_txt

console = Console()

BANNER = """
[bold red]
 

 /$$$$$$$$                                   /$$$$$$$  /$$          
| $$_____/                                  | $$__  $$|__/          
| $$       /$$$$$$$  /$$   /$$ /$$$$$$/$$$$ | $$  \ $$ /$$  /$$$$$$ 
| $$$$$   | $$__  $$| $$  | $$| $$_  $$_  $$| $$  | $$| $$ /$$__  $$
| $$__/   | $$  \ $$| $$  | $$| $$ \ $$ \ $$| $$  | $$| $$| $$  \__/
| $$      | $$  | $$| $$  | $$| $$ | $$ | $$| $$  | $$| $$| $$      
| $$$$$$$$| $$  | $$|  $$$$$$/| $$ | $$ | $$| $$$$$$$/| $$| $$      
|________/|__/  |__/ \______/ |__/ |__/ |__/|_______/ |__/|__/      


[/bold red]
[dim]Subdomain · Directory · File Enumeration Tool v0.2[/dim]
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
    if "cms" in results:
        table.add_row("Technologies detected", str(len(results["cms"])))

    console.print(table)

def print_dirs_table(dirs: list[dict], quiet: bool = False):
    """Print directory results as a table, or summary line if quiet."""
    if not dirs:
        return
    if quiet:
        console.print(f"[cyan][*] Found {len(dirs)} directories/files[/cyan]")
        return

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("Status", style="bold white", width=8)
    table.add_column("URL", style="white")
    table.add_column("Size", justify="right", style="dim")

    for entry in dirs:
        colour = STATUS_COLOURS.get(entry["status"], "white")
        table.add_row(
            f"[{colour}]{entry['status']}[/{colour}]",
            entry["url"],
            f"{entry['size']} B"
        )
    console.print(table)

STATUS_COLOURS = {
    200: "bold green",
    301: "bold yellow",
    302: "bold yellow",
    403: "bold red",
}

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="Recon Tool — Subdomain, Directory, File & CMS Enumeration",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target domain, e.g. example.com")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--dirs", action="store_true", help="Run directory/file enumeration")
    parser.add_argument("--cms", action="store_true", help="Run CMS/technology fingerprinting")
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Wordlist to use for enumeration (default: wordlists/subdomains.txt for subdomains, wordlists/directories.txt for directories)"
    )
    parser.add_argument(
    "--extensions",
    nargs="+",
    default=[],
    metavar="EXT",
    help="File extensions to probe e.g. --extensions php txt bak (default: none). Use 'all' for common extensions."
    )
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--output-json", metavar="FILE", help="Save results to a JSON file")
    parser.add_argument("--output-txt", metavar="FILE", help="Save results to a plain text file")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-result output (summary only)")
    parser.add_argument(
        "--status-codes",
        nargs="+",
        type=int,
        default=None,
        metavar="CODE",
        help="HTTP status codes to show (default: all except 404). Specify codes to show only those."
    )
    parser.add_argument(
        "--hide-status-codes",
        nargs="+",
        type=int,
        default=[404],
        metavar="CODE",
        help="HTTP status codes to hide (default: 404)"
    )

    args = parser.parse_args()

    # Handle --extensions all
    if "all" in args.extensions:
        args.extensions = ["php", "html", "htm", "aspx", "bak"]
        console.print("[cyan][*] Using common extensions: php, html, htm, aspx, bak[/cyan]")

    if args.target is None:
        console.print("[bold yellow][!] No target specified.[/bold yellow]")
        parser.print_help()
        sys.exit(1)

    results = {}
    protocol = "https" if args.https else "http"
    quiet = args.quiet

    # Handle status code filtering logic
    if args.status_codes is not None:
        # User specified codes to show
        valid_codes = args.status_codes
        hide_codes = []
    else:
        # Default: show all codes except those in hide_codes
        valid_codes = None
        hide_codes = args.hide_status_codes
    
    # Determine wordlist to use
    wordlist = args.wordlist

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
            sub_wordlist = wordlist or "wordlists/subdomains.txt"
            console.print(f"[*] Bruteforcing subdomains with wordlist: {sub_wordlist}")
            dns_results = bruteforce(args.target, sub_wordlist, args.threads, quiet=quiet)
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist not found: {sub_wordlist}[/red]")

        combined = sorted(set(ct_results + dns_results))
        results["subdomains"] = combined

        if combined:
            console.print(f"\n[bold green][+] {len(combined)} unique subdomains found:[/bold green]")
            if not quiet:
                for sub in combined:
                    console.print(f"  [green]->[/green] {sub}")
        else:
            console.print("[yellow][!] No subdomains found.[/yellow]")

    # --- Directory & File Enumeration ---
    if args.dirs:
        console.print(Panel("[bold cyan][*] Starting directory and file enumeration...[/bold cyan]", expand=False))
        base_url = f"{protocol}://{args.target}"

        try:
            dir_wordlist = wordlist or "wordlists/directories.txt"
            dir_results = enumerate_dirs(
                base_url=base_url,
                wordlist_path=dir_wordlist,
                extensions=args.extensions,
                threads=args.threads,
                timeout=args.timeout,
                valid_codes=valid_codes,
                hide_codes=hide_codes,
                quiet=quiet
            )
            results["directories"] = dir_results
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist not found: {dir_wordlist}[/red]")
            results["directories"] = []

    # --- CMS Fingerprinting ---
    if args.cms:
        console.print(Panel("[bold cyan][*] Running CMS/technology fingerprinting...[/bold cyan]", expand=False))
        base_url = f"{protocol}://{args.target}"

        try:
            cms_results = fingerprint_cms(base_url, args.timeout, args.threads)
            results["cms"] = [
                {
                    "name": r.name,
                    "confidence": r.confidence,
                    "version": r.version,
                    "indicators": r.indicators
                }
                for r in cms_results
            ]

            if cms_results:
                console.print(f"\n[bold green][+] Detected technologies:[/bold green]")
                for r in cms_results:
                    conf_color = {"high": "bold green", "medium": "bold yellow", "low": "dim"}[r.confidence]
                    console.print(f"  [{conf_color}][{r.confidence.upper()}][/{conf_color}] {r.name}")
                    if not quiet:
                        for ind in r.indicators:
                            console.print(f"    [dim]->[/dim] {ind}")
            else:
                console.print("[yellow][!] No CMS detected.[/yellow]")
        except Exception as e:
            console.print(f"[red][!] CMS fingerprinting failed: {e}[/red]")

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
