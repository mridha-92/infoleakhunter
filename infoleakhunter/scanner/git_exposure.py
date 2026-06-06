from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.git_exposure")

GIT_PATHS = [
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".git/refs/heads/develop",
    ".git/refs/remotes/origin/HEAD",
    ".git/description",
    ".git/info/exclude",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".git/FETCH_HEAD",
    ".git/ORIG_HEAD",
    ".git/packed-refs",
]

GIT_CONFIG_INDICATORS = [
    r"\[core\]",
    r"\[remote",
    r"\[branch",
    r"repositoryformatversion",
    r"filemode",
    r"bare\s*=\s*false",
]

GIT_HEAD_INDICATORS = [
    r"ref:\s*refs/heads/",
    r"^[a-f0-9]{40}$",
]


class GitExposureScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        for path in GIT_PATHS:
            try:
                test_url = self.normalize_url(path)
                status, headers, body, cookies = await self.http_client.check_url(test_url, timeout=15)

                if status == 200 and body:
                    self._analyze_git_content(body, path, test_url)

            except Exception as e:
                logger.debug(f"Error scanning git path {path} on {self.target}: {e}")

        try:
            git_url = self.normalize_url(".git/")
            status, headers, body, cookies = await self.http_client.check_url(git_url)
            if status == 200:
                if "Index of" in body or "HEAD" in body or "config" in body:
                    finding = create_finding(
                        target=self.target,
                        module="git_exposure",
                        title="Git directory listing exposed",
                        evidence=f"URL: {git_url}\nDirectory listing of .git available",
                        url=git_url,
                        status_code=200,
                        tags=["git", "directory-listing"],
                    )
                    self.findings.add(finding)
        except Exception:
            pass

        return self.findings

    def _analyze_git_content(self, body: str, path: str, url: str) -> None:
        if path == ".git/config":
            for indicator in GIT_CONFIG_INDICATORS:
                if re.search(indicator, body, re.MULTILINE):
                    evidence = self._extract_git_evidence(body)
                    finding = create_finding(
                        target=self.target,
                        module="git_exposure",
                        title="Git repository configuration exposed (.git/config)",
                        evidence=evidence,
                        url=url,
                        status_code=200,
                        description="The .git/config file is publicly accessible, exposing repository metadata",
                        tags=["git", "git-config"],
                    )
                    self.findings.add(finding)
                    return

        elif path == ".git/HEAD":
            for indicator in GIT_HEAD_INDICATORS:
                if re.search(indicator, body, re.MULTILINE):
                    branch = body.strip().replace("ref: refs/heads/", "")
                    evidence = f"Git HEAD exposed\nBranch: {branch}\nContent: {body.strip()[:200]}"
                    finding = create_finding(
                        target=self.target,
                        module="git_exposure",
                        title=f"Git HEAD reference exposed (branch: {branch})",
                        evidence=evidence,
                        url=url,
                        status_code=200,
                        tags=["git", "git-head"],
                    )
                    self.findings.add(finding)
                    return

        elif path == ".git/index":
            if body and len(body) > 20:
                evidence = f"Git index file exposed ({len(body)} bytes)"
                finding = create_finding(
                    target=self.target,
                    module="git_exposure",
                    title="Git index file exposed (potential full repo download)",
                    evidence=evidence,
                    url=url,
                    status_code=200,
                    tags=["git", "git-index"],
                )
                self.findings.add(finding)

        elif path in (".git/logs/HEAD", ".git/refs/heads/master", ".git/refs/heads/main"):
            if body.strip():
                evidence = f"Git reference exposed\nPath: {path}\nContent:\n{body.strip()[:500]}"
                finding = create_finding(
                    target=self.target,
                    module="git_exposure",
                    title=f"Git metadata exposed: {path}",
                    evidence=evidence,
                    url=url,
                    status_code=200,
                    tags=["git", "git-metadata"],
                )
                self.findings.add(finding)

        else:
            if body.strip():
                evidence = f"Git file exposed\nPath: {path}\nContent preview: {body.strip()[:200]}"
                finding = create_finding(
                    target=self.target,
                    module="git_exposure",
                    title=f"Git repository file exposed: {path}",
                    evidence=evidence,
                    url=url,
                    status_code=200,
                    tags=["git", "git-metadata"],
                )
                self.findings.add(finding)

    def _extract_git_evidence(self, body: str) -> str:
        lines = body.strip().split("\n")
        relevant = []
        for line in lines:
            stripped = line.strip()
            if stripped and (stripped.startswith("[") or "=" in stripped or "url =" in stripped):
                relevant.append(stripped)
        if not relevant:
            relevant = lines[:20]
        evidence = "Git Config Content:\n" + "\n".join(relevant[:20])
        if len(lines) > 20:
            evidence += f"\n... ({len(lines) - 20} more lines)"
        return evidence[:1000]
