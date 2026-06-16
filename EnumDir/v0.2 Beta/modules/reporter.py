import json
from datetime import datetime


def save_json(results: dict, filepath: str) -> None:
    """Save results to a JSON file with a timestamp."""
    output = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


def save_txt(results: dict, filepath: str) -> None:
    """Save results to a plain text file."""
    lines = []
    lines.append(f"Recon Tool — Scan Results")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("=" * 60)

    if "subdomains" in results:
        lines.append("\n[SUBDOMAINS]")
        if results["subdomains"]:
            for sub in results["subdomains"]:
                lines.append(f"  {sub}")
        else:
            lines.append("  None found.")

    if "directories" in results:
        lines.append("\n[DIRECTORIES & FILES]")
        if results["directories"]:
            for entry in results["directories"]:
                lines.append(f"  [{entry['status']}] {entry['url']} ({entry['size']} bytes)")
        else:
            lines.append("  None found.")

    if "cms" in results:
        lines.append("\n[CMS / TECHNOLOGIES]")
        if results["cms"]:
            for entry in results["cms"]:
                lines.append(f"  [{entry['confidence'].upper()}] {entry['name']}")
                if entry.get("indicators"):
                    for ind in entry["indicators"]:
                        lines.append(f"    -> {ind}")
                if entry.get("version"):
                    lines.append(f"    Version: {entry['version']}")
        else:
            lines.append("  None detected.")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
