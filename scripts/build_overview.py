
#!/usr/bin/env python3
import argparse
import os
import re
import sys
import yaml
import requests
from pathlib import Path
from typing import Dict, Tuple, Optional, List

GITHUB_API = "https://api.github.com"

def parse_repo(url: str) -> Tuple[str, str]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/|$)", url.strip())
    if not m:
        raise ValueError(f"Not a GitHub repo URL: {url}")
    return m.group(1), m.group(2)

def get_token() -> Optional[str]:
    return os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")

def fetch_dependabot_counts(owner: str, repo: str, session: requests.Session):
    headers = {"Accept": "application/vnd.github+json"}
    token = get_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    url = f"{GITHUB_API}/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100"
    total = 0
    severities = {"critical": 0, "high": 0, "moderate": 0, "low": 0}

    while url:
        r = session.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            return (None, {}, {"reason": "not_found"})
        if r.status_code == 403:
            msg = (r.text or "").lower()
            if "archived" in msg:
                return (None, {}, {"archived": True, "reason": "archived"})
            return (None, {}, {"reason": "forbidden"})
        if r.status_code == 401:
            return (None, {}, {"reason": "unauthorized"})
        r.raise_for_status()

        data = r.json()
        if not isinstance(data, list):
            return (None, {}, {"reason": "unexpected"})

        total += len(data)
        for alert in data:
            sev = (
                ((alert.get("security_vulnerability") or {}).get("severity"))
                or ((alert.get("security_advisory") or {}).get("severity"))
                or alert.get("severity")
            )
            if isinstance(sev, str):
                sev_l = sev.lower()
                if sev_l in severities:
                    severities[sev_l] += 1

        link = r.headers.get("Link", "")
        next_url = None
        if link:
            for part in [p.strip() for p in link.split(",")]:
                if 'rel="next"' in part:
                    m = re.search(r'<([^>]+)>', part)
                    if m:
                        next_url = m.group(1)
                        break
        url = next_url

    return (total, severities, {"reason": "ok"})

def md_link(label: str, url: str) -> str:
    return f"[{label}"


def build_standard_table(cfg: dict) -> str:
    header = (
        "| Type | ÜK/Module | ÜK Number | Repository Name | Repository URL |\n"
        "|------|-----------|-----------|----------------|----------------|\n"
    )
    lines = [header]
    for module in cfg["modules"]:
        mtype = module.get("type", "")
        uek = module.get("uek", module.get("module", ""))
        uek_number = str(module.get("uek_number", "")) if "uek_number" in module else ""
        for repo in module.get("repos", []):
            name = repo.get("name", "")
            url = repo.get("url", "")
            # Markdown link for the repo name
            link = f"[{name}]({f url else ""
            lines.append(
                f"| {mtype} | {uek} | {uek_number} | {name} | {link} |"
            )
    return "\n".join(lines)

def build_alerts_table(cfg: dict) -> str:
    session = requests.Session()
    rows: List[dict] = []

    def consider_repo(module_name: str, repo_name: str, repo_url: str):
        if not repo_url:
            return
        try:
            owner, repo = parse_repo(repo_url)
        except ValueError:
            return
        total, sev, meta = fetch_dependabot_counts(owner, repo, session)
        if not isinstance(total, int) or total <= 0:
            return
        row = {
            "module": module_name,
            "repo_name": repo_name,
            "url": repo_url,
            "open": total,
            "critical": int(sev.get("critical", 0)) if isinstance(sev, dict) else "",
            "high": int(sev.get("high", 0)) if isinstance(sev, dict) else "",
            "moderate": int(sev.get("moderate", 0)) if isinstance(sev, dict) else "",
            "low": int(sev.get("low", 0)) if isinstance(sev, dict) else "",
        }
        rows.append(row)

    for module in cfg["modules"]:
        module_name = module.get("uek", module.get("module", ""))
        for repo in module.get("repos", []):
            repo_name = repo.get("name", "")
            repo_url = repo.get("url", "")
            consider_repo(module_name, repo_name, repo_url)

    rows.sort(key=lambda r: (-r["open"], r["module"], r["repo_name"]))

    if not rows:
        return "_No open Dependabot alerts across listed repositories._\n"

    header = "| Module | Repo | Open | Critical | High | Moderate | Low |\n"
    sep = "|------|------|-----:|--------:|-----:|---------:|----:|\n"
    lines = [header, sep]
    for r in rows:
        repo_link = md_link(r["repo_name"], r["url"])
        lines.append(f"| **{r['module']}** | {repo_link} | {r['open']} | {r['critical']} | {r['high']} | {r['moderate']} | {r['low']} |\n")
    return "".join(lines)

def replace_between_markers(text: str, start_marker: str, end_marker: str, replacement: str) -> str:
    pattern = re.compile(re.escape(start_marker) + r".*?" + re.escape(end_marker), re.DOTALL)
    block = f"{start_marker}\n\n{replacement}\n{end_marker}"
    if pattern.search(text):
        return pattern.sub(block, text, count=1)
    return text.rstrip() + "\n\n" + block + "\n"

def main():
    p = argparse.ArgumentParser(description="Build Campus Module overview and alerts tables.")
    p.add_argument("--config", default="data/tools.yaml")
    p.add_argument("--output-md", default="Campus_Module_Consolidated.md")
    p.add_argument("--update-readme", default="")
    p.add_argument("--start-marker", default="<!-- CAMPUS-OVERVIEW:START -->")
    p.add_argument("--end-marker", default="<!-- CAMPUS-OVERVIEW:END -->")
    args = p.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))

    # Compose final content
    title = "# 🎓 Campus Applications — Consolidated Overview\n\n"
    standard = build_standard_table(cfg)
    alerts_title = "\n\n## ⚠️ Dependabot Alerts — Weekly Snapshot\n\n_Note: only repositories with **> 0** open alerts are listed. Archived tools are hidden. Sorted by open alerts (desc)._\n\n"
    alerts_table = build_alerts_table(cfg)
    content = title + standard + alerts_title + alerts_table + "\n"

    if args.update_readme:
        readme_path = Path(args.update_readme)
        src = readme_path.read_text(encoding="utf-8")
        updated = replace_between_markers(src, args.start_marker, args.end_marker, content)
        readme_path.write_text(updated, encoding="utf-8")
        print(f"Updated section in {args.update_readme}")
    else:
        Path(args.output_md).write_text(content, encoding="utf-8")
        print(f"Wrote {args.output_md}")

if __name__ == "__main__":
    main()
