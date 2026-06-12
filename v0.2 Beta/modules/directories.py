import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

STATUS_COLOURS = {
    200: "bold green",
    301: "bold yellow",
    302: "bold yellow",
    403: "bold red",
}


def _colour_for_status(code: int) -> str:
    return STATUS_COLOURS.get(code, "white")


def check_path(
    base_url: str,
    path: str,
    extensions: list[str] | None,
    timeout: int,
    valid_codes: list[int] | None,
    session: requests.Session,
    hide_codes: list[int] | None = None,
    quiet: bool = False,
) -> list[dict]:
    """
    Check a single path and optionally append file extensions.
    Returns a list of findings (may be empty).
    """
    found = []

    targets = [path]
    if extensions:
        for ext in extensions:
            targets.append(f"{path}.{ext}")

    for target in targets:
        url = f"{base_url}/{target.lstrip('/')}"
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)
            # Determine if we should include this response
            should_include = False
            if valid_codes is not None:
                # If valid_codes is specified, only include if status is in that list
                should_include = resp.status_code in valid_codes
            elif hide_codes is not None:
                # If hide_codes is specified, include if status is NOT in that list
                should_include = resp.status_code not in hide_codes
            else:
                # Default: include all responses
                should_include = True

            if should_include:
                entry = {
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                }
                found.append(entry)
                if not quiet:
                    colour = _colour_for_status(resp.status_code)
                    console.print(
                        f"  [{colour}][{resp.status_code}][/{colour}] "
                        f"{url} [dim]({entry['size']} bytes)[/dim]"
                    )
        except requests.RequestException:
            pass

    return found


def enumerate_dirs(
    base_url: str,
    wordlist_path: str,
    extensions: list[str] | None = None,
    threads: int = 20,
    timeout: int = 5,
    valid_codes: list[int] | None = None,
    hide_codes: list[int] | None = None,
    quiet: bool = False,
) -> list[dict]:
    """
    Enumerate directories and files against base_url using a wordlist.
    
    Args:
        valid_codes: If specified, only include these status codes
        hide_codes: If valid_codes is None, exclude these status codes (default behavior)
    """
    if hide_codes is None:
        hide_codes = []

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    console.print(f"[*] Loaded {len(words)} words from {wordlist_path}")
    console.print(f"[*] Extensions: {', '.join(extensions) if extensions else 'none'}")
    console.print(f"[*] Target: {base_url}\n")

    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": "recon-tool/1.0"})

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[green]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(words))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    check_path, base_url, word, extensions, timeout, valid_codes, session, hide_codes, quiet
                ): word
                for word in words
            }
            for future in as_completed(futures):
                findings = future.result()
                results.extend(findings)
                progress.advance(task)

    session.close()
    results.sort(key=lambda x: x["url"])
    return results