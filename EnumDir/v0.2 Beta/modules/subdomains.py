import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


def check_subdomain(subdomain: str, domain: str, quiet: bool = False) -> str | None:
    """
    Attempt to resolve a subdomain via DNS.
    Returns the FQDN if it resolves, otherwise None.
    """
    fqdn = f"{subdomain}.{domain}"
    try:
        dns.resolver.resolve(fqdn, "A")
        if not quiet:
            console.print(f"  [green][+] Found (DNS):[/green] {fqdn}")
        return fqdn
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout,
            dns.exception.DNSException):
        return None


def bruteforce(domain: str, wordlist_path: str, threads: int = 50, quiet: bool = False) -> list[str]:
    """
    Bruteforce subdomains using a wordlist and concurrent DNS lookups.
    """
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    console.print(f"[*] Loaded {len(words)} words from {wordlist_path}")
    found = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        TextColumn("[green]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Bruteforcing DNS...", total=len(words))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, word, domain, quiet): word for word in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                progress.advance(task)

    return found


def crt_sh(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency logs for known subdomains.
    Completely passive — no requests sent to the target.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "recon-tool/1.0"}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        entries = resp.json()
    except requests.RequestException as e:
        raise RuntimeError(f"crt.sh request failed: {e}")
    except ValueError:
        raise RuntimeError("crt.sh returned invalid JSON")

    subdomains = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(domain) and " " not in name:
                subdomains.add(name)

    return sorted(subdomains)
