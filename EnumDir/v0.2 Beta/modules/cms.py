import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from dataclasses import dataclass
from typing import Optional

console = Console()


@dataclass
class CMSResult:
    name: str
    confidence: str  # "high", "medium", "low"
    version: Optional[str]
    indicators: list[str]


CMS_SIGNATURES = {
    "WordPress": {
        "high": [
            "/wp-login.php",
            "/wp-admin/",
            "/wp-content/",
            "/wp-includes/",
            "/xmlrpc.php",
            "/wp-json/wp/v2/",
        ],
        "medium": [
            "/readme.html",
            "/license.txt",
            "/wp-trackback.php",
            "/wp-cron.php",
        ],
        "version_files": [
            "/wp-includes/js/wp-embed.min.js",
            "/wp-includes/css/dashicons.min.css",
        ],
        "headers": ["x-powered-by: php"],
        "meta_patterns": ['name="generator" content="WordPress"'],
    },
    "Joomla": {
        "high": [
            "/administrator/",
            "/administrator/index.php",
            "/media/jui/js/",
            "/modules/",
            "/components/",
            "/includes/js/joomla.jquery.js",
        ],
        "medium": [
            "/configuration.php",
            "/README.txt",
            "/LICENSE.php",
        ],
        "version_files": [],
        "headers": [],
        "meta_patterns": ['name="generator" content="Joomla!"'],
    },
    "Drupal": {
        "high": [
            "/core/POWERED_BY.txt",
            "/core/assets/",
            "/modules/",
            "/themes/",
            "/sites/default/",
            "/CHANGELOG.txt",
        ],
        "medium": [
            "/README.txt",
            "/UPGRADE.txt",
            "/INSTALL.txt",
        ],
        "version_files": [],
        "headers": [],
        "meta_patterns": ['name="generator" content="Drupal"'],
    },
    "Magento": {
        "high": [
            "/pub/static/",
            "/static/frontend/",
            "/media/",
            "/skin/frontend/",
            "/downloader/",
            "/get.php",
        ],
        "medium": [
            "/errors/",
            "/var/",
            "/shell/",
        ],
        "version_files": [],
        "headers": [],
        "meta_patterns": [],
    },
    "Shopify": {
        "high": [],
        "medium": [],
        "version_files": [],
        "headers": ["x-shopify-stage", "x-shopify-production"],
        "meta_patterns": [],
    },
    "WooCommerce": {
        "high": [
            "/wp-content/plugins/woocommerce/",
            "/wp-content/plugins/woo-includes/",
        ],
        "medium": [
            "/wp-content/plugins/woocommerce-currency-switcher/",
        ],
        "version_files": [],
        "headers": [],
        "meta_patterns": [],
    },
    "Ghost": {
        "high": [
            "/ghost/",
            "/api/v2/content/",
            "/assets/ghost/",
        ],
        "medium": [
            "/content/images/",
            "/members/",
        ],
        "version_files": [],
        "headers": [],
        "meta_patterns": ['name="generator" content="Ghost"'],
    },
    "Hugo": {
        "high": [
            "/css/",
            "/js/",
            "/images/",
        ],
        "medium": [],
        "version_files": [],
        "headers": [],
        "meta_patterns": [],
    },
    "Next.js": {
        "high": [
            "/_next/static/",
            "/_next/data/",
        ],
        "medium": [],
        "version_files": [],
        "headers": ["x-nextjs-"],
        "meta_patterns": [],
    },
    "React": {
        "high": [],
        "medium": [
            "/static/js/",
            "/static/css/",
            "/asset-manifest.json",
        ],
        "version_files": [],
        "headers": [],
        "meta_patterns": [],
    },
    "PHP": {
        "high": [],
        "medium": [],
        "version_files": [],
        "headers": ["x-powered-by: php"],
        "meta_patterns": [],
    },
    "Apache": {
        "high": [],
        "medium": [],
        "version_files": [],
        "headers": ["server: apache"],
        "meta_patterns": [],
    },
    "Nginx": {
        "high": [],
        "medium": [],
        "version_files": [],
        "headers": ["server: nginx"],
        "meta_patterns": [],
    },
}


def check_cms_indicator(base_url: str, path: str, timeout: int, session: requests.Session) -> bool:
    """Check if a single CMS indicator exists."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
        return resp.status_code in [200, 301, 302, 403]
    except requests.RequestException:
        return False


def check_header_indicator(headers: dict, signature: str) -> bool:
    """Check if a header matches the signature pattern."""
    parts = signature.split(": ", 1)
    if len(parts) == 2:
        header_name = parts[0].lower()
        header_value = parts[1].lower()
        for name, value in headers.items():
            if name.lower() == header_name and header_value in value.lower():
                return True
    return False


def check_meta_pattern(html: str, pattern: str) -> bool:
    """Check if HTML contains a meta generator pattern."""
    return pattern in html


def fingerprint_cms(base_url: str, timeout: int = 5, threads: int = 20) -> list[CMSResult]:
    """
    Attempt to identify the CMS/technology running on a target.
    Checks multiple indicators concurrently.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "recon-tool/1.0"})

    results: list[CMSResult] = []

    # Collect all checks
    all_checks: list[tuple[str, str, str]] = []  # (cms_name, indicator_type, indicator)
    for cms_name, sigs in CMS_SIGNATURES.items():
        for ind in sigs.get("high", []):
            all_checks.append((cms_name, "high", ind))
        for ind in sigs.get("medium", []):
            all_checks.append((cms_name, "medium", ind))
        for ind in sigs.get("headers", []):
            all_checks.append((cms_name, "header", ind))
        for ind in sigs.get("meta_patterns", []):
            all_checks.append((cms_name, "meta", ind))

    # Get homepage for header and meta checks
    try:
        resp = session.get(base_url, timeout=timeout, allow_redirects=True)
        html = resp.text
        headers = dict(resp.headers)
    except requests.RequestException:
        html = ""
        headers = {}

    # Separate URL checks from header/meta checks
    url_checks = [(cms, level, ind) for cms, level, ind in all_checks if level in ("high", "medium")]
    other_checks = [(cms, level, ind) for cms, level, ind in all_checks if level not in ("high", "medium")]

    # Check header/meta patterns first
    for cms_name, level, pattern in other_checks:
        if level == "header":
            if check_header_indicator(headers, pattern):
                results.append(CMSResult(
                    name=cms_name,
                    confidence="medium",
                    version=None,
                    indicators=[f"Header match: {pattern}"]
                ))
        elif level == "meta":
            if check_meta_pattern(html, pattern):
                results.append(CMSResult(
                    name=cms_name,
                    confidence="high",
                    version=None,
                    indicators=[f"Meta tag: {pattern}"]
                ))

    # Check URL paths concurrently
    if url_checks:
        path_checks = [(cms, level, ind) for cms, level, ind in url_checks]
        found_indicators: dict[str, list[str]] = {}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_cms_indicator, base_url, path, timeout, session): (cms, level, path)
                for cms, level, path in path_checks
            }
            for future in as_completed(futures):
                cms, level, path = futures[future]
                if future.result():
                    if cms not in found_indicators:
                        found_indicators[cms] = []
                    found_indicators[cms].append(path)

        # Determine confidence based on high vs medium indicators
        for cms_name, indicators in found_indicators.items():
            sigs = CMS_SIGNATURES.get(cms_name, {})
            high_count = sum(1 for i in indicators if i in sigs.get("high", []))
            medium_count = sum(1 for i in indicators if i in sigs.get("medium", []))

            if high_count > 0:
                confidence = "high" if high_count >= 2 else "medium"
            else:
                confidence = "medium" if medium_count >= 2 else "low"

            results.append(CMSResult(
                name=cms_name,
                confidence=confidence,
                version=None,
                indicators=indicators[:5]  # Limit shown indicators
            ))

    session.close()

    # Sort by confidence
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda x: confidence_order.get(x.confidence, 3))

    return results