from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.metadata")

METADATA_EXTENSIONS = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
}

COMMON_DOC_PATHS = [
    "documentation.pdf", "manual.pdf", "guide.pdf", "report.pdf",
    "resume.pdf", "cv.pdf", "brochure.pdf", "whitepaper.pdf",
    "financial_report.xlsx", "budget.xlsx", "spreadsheet.xlsx",
    "presentation.pptx", "slides.pptx", "deck.pptx",
    "policy.docx", "procedures.docx", "contract.docx", "agreement.docx",
    "docs/manual.pdf", "docs/guide.pdf",
    "static/docs/manual.pdf",
    "uploads/document.pdf",
    "files/document.pdf",
    "assets/docs/manual.pdf",
]


class MetadataScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        if not self.config.get("scan", {}).get("download_metadata", True):
            return self.findings

        for doc_path in COMMON_DOC_PATHS:
            try:
                url = self.normalize_url(doc_path)
                status, headers, body_bytes, cookies = await self.http_client.check_url_binary(url)

                if status == 200 and body_bytes:
                    content_type = headers.get("Content-Type", "")
                    ext = "." + doc_path.rsplit(".", 1)[-1].lower() if "." in doc_path else ""

                    self._analyze_metadata(body_bytes, url, ext, content_type)

            except Exception as e:
                logger.debug(f"Error scanning metadata for {doc_path} on {self.target}: {e}")

        return self.findings

    def _analyze_metadata(self, content: bytes | str, url: str, ext: str, content_type: str) -> None:
        if isinstance(content, str):
            content = content.encode("utf-8", errors="replace")

        if ext == ".pdf" or "pdf" in content_type.lower():
            self._analyze_pdf(content, url)
        elif ext in (".docx", ".xlsx", ".pptx") or "openxml" in content_type.lower():
            self._analyze_ooxml(content, url, ext)
        else:
            self._analyze_binary_metadata(content, url)

    def _analyze_pdf(self, content: bytes, url: str) -> None:
        text = content.decode("utf-8", errors="replace")

        author_match = re.search(r"/Author\s*\(([^)]*)\)", text, re.I)
        creator_match = re.search(r"/Creator\s*\(([^)]*)\)", text, re.I)
        producer_match = re.search(r"/Producer\s*\(([^)]*)\)", text, re.I)
        title_match = re.search(r"/Title\s*\(([^)]*)\)", text, re.I)
        subject_match = re.search(r"/Subject\s*\(([^)]*)\)", text, re.I)
        created_match = re.search(r"/CreationDate\s*\(([^)]*)\)", text, re.I)
        modified_match = re.search(r"/ModDate\s*\(([^)]*)\)", text, re.I)

        metadata = {}
        if author_match:
            metadata["Author"] = author_match.group(1)
        if creator_match:
            metadata["Creator"] = creator_match.group(1)
        if producer_match:
            metadata["Producer"] = producer_match.group(1)
        if title_match:
            metadata["Title"] = title_match.group(1)
        if subject_match:
            metadata["Subject"] = subject_match.group(1)
        if created_match:
            metadata["CreationDate"] = created_match.group(1)
        if modified_match:
            metadata["ModDate"] = modified_match.group(1)

        if metadata:
            evidence = "\n".join(f"{k}: {v}" for k, v in metadata.items())
            finding = create_finding(
                target=self.target,
                module="metadata",
                title="PDF metadata exposed",
                evidence=evidence,
                url=url,
                status_code=200,
                tags=["metadata", "pdf"],
            )
            self.findings.add(finding)

            if "Author" in metadata and metadata["Author"] not in ("", "Unknown", "unknown"):
                finding2 = create_finding(
                    target=self.target,
                    module="metadata",
                    title=f"Document author disclosed: {metadata['Author']}",
                    evidence=f"Author: {metadata['Author']}",
                    url=url,
                    status_code=200,
                    tags=["metadata", "pdf", "author"],
                )
                self.findings.add(finding2)

        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        for email in set(emails[:5]):
            if "example" not in email:
                finding = create_finding(
                    target=self.target,
                    module="metadata",
                    title=f"Email address in PDF metadata: {email}",
                    evidence=f"Email: {email}",
                    url=url,
                    status_code=200,
                    tags=["metadata", "pdf", "email"],
                )
                self.findings.add(finding)

        paths = re.findall(r'/(?:var|home|Users|tmp|opt|etc|usr)/[^\s\(\)<>"]+', text)
        for path in set(paths[:5]):
            if any(ext in path for ext in [".php", ".py", ".js", ".java", ".conf", ".ini", ".xml", ".json", ".yml"]):
                continue
            finding = create_finding(
                target=self.target,
                module="metadata",
                title=f"Internal path in PDF metadata: {path}",
                evidence=f"Path: {path}",
                url=url,
                status_code=200,
                tags=["metadata", "pdf", "internal-path"],
            )
            self.findings.add(finding)

    def _analyze_ooxml(self, content: bytes, url: str, ext: str) -> None:
        import zipfile
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                if "docProps/core.xml" in zf.namelist():
                    core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                    metadata = {}

                    author = re.search(r"<dc:creator>([^<]+)</dc:creator>", core_xml)
                    if author:
                        metadata["Author"] = author.group(1)

                    modified_by = re.search(r"<cp:lastModifiedBy>([^<]+)</cp:lastModifiedBy>", core_xml)
                    if modified_by:
                        metadata["LastModifiedBy"] = modified_by.group(1)

                    created = re.search(r"<dcterms:created[^>]*>([^<]+)</dcterms:created>", core_xml)
                    if created:
                        metadata["Created"] = created.group(1)

                    modified = re.search(r"<dcterms:modified[^>]*>([^<]+)</dcterms:modified>", core_xml)
                    if modified:
                        metadata["Modified"] = modified.group(1)

                    revision = re.search(r"<cp:revision>([^<]+)</cp:revision>", core_xml)
                    if revision:
                        metadata["Revision"] = revision.group(1)

                    if metadata:
                        evidence = "\n".join(f"{k}: {v}" for k, v in metadata.items())
                        file_type = ext.upper().replace(".", "")
                        finding = create_finding(
                            target=self.target,
                            module="metadata",
                            title=f"{file_type} document metadata exposed",
                            evidence=evidence,
                            url=url,
                            status_code=200,
                            tags=["metadata", file_type.lower()],
                        )
                        self.findings.add(finding)

        except Exception as e:
            logger.debug(f"Error analyzing OOXML metadata for {url}: {e}")

    def _analyze_binary_metadata(self, content: bytes, url: str) -> None:
        try:
            text = content.decode("utf-8", errors="replace")
            authors = re.findall(r"(?:Author|Creator)\s*[:\-]\s*([^\r\n]{1,100})", text, re.I)
            for author in set(authors[:3]):
                author = author.strip().strip('"').strip("'")
                if author and author not in ("", "Unknown", "unknown"):
                    finding = create_finding(
                        target=self.target,
                        module="metadata",
                        title=f"Document metadata author: {author}",
                        evidence=f"Author: {author}",
                        url=url,
                        status_code=200,
                        tags=["metadata", "author"],
                    )
                    self.findings.add(finding)
        except Exception:
            pass
