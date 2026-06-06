from __future__ import annotations

import logging
import re
import socket
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.dns")

INTERNAL_IP_PATTERNS = re.compile(
    r"(?:^|\.)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:$|\.)"
)

INTERNAL_HOSTNAME_PATTERNS = re.compile(
    r"(?:^|\.)(?:dev|stage|staging|qa|test|uat|internal|private|admin|jenkins|gitlab|jira|confluence|wiki|mail|vpn|ns[0-9]|dc[0-9]|db[0-9])(?:\.|$)",
    re.I,
)

SUBDOMAINS_TO_CHECK = [
    "dev", "stage", "staging", "qa", "test", "uat", "admin", "portal",
    "mail", "vpn", "remote", "intranet", "internal", "private",
    "jenkins", "gitlab", "jira", "confluence", "wiki",
    "api", "api-dev", "api-staging", "api-qa",
    "app", "app-dev", "app-staging",
    "dashboard", "monitor", "grafana", "kibana", "prometheus",
    "db", "database", "mysql", "postgres",
    "backup", "backups", "storage", "files",
    "s3", "bucket", "assets", "cdn",
]


class DNSLeakageScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        if not self.config.get("scan", {}).get("dns_lookups", True):
            return self.findings

        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        hostname = parsed.hostname or parsed.netloc or self.target

        try:
            await self._check_txt_records(hostname)
            await self._check_subdomains(hostname)
            await self._check_dns_entries(hostname)
        except Exception as e:
            logger.debug(f"Error in DNS scanning for {hostname}: {e}")

        return self.findings

    async def _check_txt_records(self, hostname: str) -> None:
        try:
            import dns.resolver

            for record_type in ["TXT", "SPF", "MX", "CNAME", "NS", "SOA"]:
                try:
                    answers = dns.resolver.resolve(hostname, record_type, lifetime=10)
                    for answer in answers:
                        text = str(answer)
                        if record_type == "TXT":
                            self._analyze_txt_record(text, hostname)
                        elif record_type == "MX":
                            if any(k in text.lower() for k in ["dev", "stage", "test", "internal", "local"]):
                                finding = create_finding(
                                    target=self.target,
                                    module="dns",
                                    title=f"Development-related MX record: {text.strip()}",
                                    evidence=f"MX: {text.strip()}",
                                    tags=["dns", "mx", "internal"],
                                )
                                self.findings.add(finding)

                        elif record_type == "CNAME":
                            if any(k in text.lower() for k in ["dev", "stage", "staging", "test", "qa", "internal"]):
                                finding = create_finding(
                                    target=self.target,
                                    module="dns",
                                    title=f"Development-related CNAME record: {text.strip()}",
                                    evidence=f"CNAME: {text.strip()}",
                                    tags=["dns", "cname", "internal"],
                                )
                                self.findings.add(finding)

                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    continue
                except Exception as e:
                    logger.debug(f"DNS lookup error for {hostname} {record_type}: {e}")

        except ImportError:
            logger.debug("dnspython not installed, skipping DNS TXT analysis")
        except Exception as e:
            logger.debug(f"DNS resolution error for {hostname}: {e}")

    def _analyze_txt_record(self, text: str, hostname: str) -> None:
        if INTERNAL_IP_PATTERNS.search(text):
            ips = INTERNAL_IP_PATTERNS.findall(text)
            evidence = f"DNS TXT Record: {text}\nInternal IP: {', '.join(ips)}"
            finding = create_finding(
                target=self.target,
                module="dns",
                title="Internal IP address disclosed in DNS TXT record",
                evidence=evidence,
                tags=["dns", "txt", "internal-ip"],
            )
            self.findings.add(finding)

        if INTERNAL_HOSTNAME_PATTERNS.search(text):
            hosts = INTERNAL_HOSTNAME_PATTERNS.findall(text)
            evidence = f"DNS TXT Record: {text}\nInternal hostname reference: {', '.join(hosts)}"
            finding = create_finding(
                target=self.target,
                module="dns",
                title="Internal hostname reference in DNS TXT record",
                evidence=evidence,
                tags=["dns", "txt", "internal-host"],
            )
            self.findings.add(finding)

        spf_match = re.search(r"v=spf1", text, re.I)
        if spf_match and any(k in text for k in ["include:", "redirect=", "a:", "mx:", "ptr:"]):
            include_refs = re.findall(r"include:([^\s]+)", text)
            for ref in include_refs:
                if any(k in ref.lower() for k in ["dev", "stage", "test", "internal", "mail"]):
                    finding = create_finding(
                        target=self.target,
                        module="dns",
                        title=f"SPF record includes internal/development reference: {ref}",
                        evidence=f"SPF include: {ref}",
                        tags=["dns", "spf", "internal"],
                    )
                    self.findings.add(finding)

        dkim = re.search(r"v=DKIM1", text, re.I)
        if dkim:
            selectors = re.findall(r"s=([^\s;]+)", text)
            for selector in selectors:
                finding = create_finding(
                    target=self.target,
                    module="dns",
                    title=f"DKIM selector disclosed: {selector}",
                    evidence=f"DKIM Record: selector={selector}",
                    tags=["dns", "dkim"],
                )
                self.findings.add(finding)

        dmarc = re.search(r"v=DMARC1", text, re.I)
        if dmarc:
            policies = re.findall(r"p=(\w+)", text)
            if policies and "reject" not in policies:
                evidence = f"DMARC Record: {text}"
                finding = create_finding(
                    target=self.target,
                    module="dns",
                    title=f"DMARC policy not set to reject (currently: {policies[0]})",
                    evidence=evidence,
                    tags=["dns", "dmarc"],
                )
                self.findings.add(finding)

    async def _check_subdomains(self, hostname: str) -> None:
        for subdomain in SUBDOMAINS_TO_CHECK:
            try:
                test_host = f"{subdomain}.{hostname}"
                ip = await asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyname, test_host
                )
                if ip:
                    import ipaddress
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            finding = create_finding(
                                target=self.target,
                                module="dns",
                                title=f"Development subdomain resolves to internal IP: {test_host} -> {ip}",
                                evidence=f"Subdomain: {test_host}\nIP: {ip}",
                                tags=["dns", "subdomain", "internal-ip"],
                            )
                            self.findings.add(finding)
                        else:
                            finding = create_finding(
                                target=self.target,
                                module="dns",
                                title=f"Development subdomain resolves: {test_host} -> {ip}",
                                evidence=f"Subdomain: {test_host}\nIP: {ip}",
                                tags=["dns", "subdomain"],
                            )
                            self.findings.add(finding)
                    except ValueError:
                        pass
            except (socket.gaierror, OSError):
                continue

    async def _check_dns_entries(self, hostname: str) -> None:
        try:
            ips = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyname_ex, hostname
            )
            host_ips = ips[2]

            for ip in host_ips:
                try:
                    import ipaddress
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        finding = create_finding(
                            target=self.target,
                            module="dns",
                            title=f"Hostname resolves to internal IP: {hostname} -> {ip}",
                            evidence=f"Hostname: {hostname}\nIP: {ip}",
                            tags=["dns", "internal-ip"],
                        )
                        self.findings.add(finding)

                    try:
                        hostnames = await asyncio.get_event_loop().run_in_executor(
                            None, socket.gethostbyaddr, ip
                        )
                        ptr = hostnames[0]
                        if any(k in ptr.lower() for k in ["dev", "stage", "staging", "qa", "test", "uat", "internal"]):
                            finding = create_finding(
                                target=self.target,
                                module="dns",
                                title=f"Reverse DNS shows development hostname: {ip} -> {ptr}",
                                evidence=f"IP: {ip}\nPTR: {ptr}",
                                tags=["dns", "reverse-dns", "internal"],
                            )
                            self.findings.add(finding)
                    except (socket.herror, OSError):
                        pass

                except ValueError:
                    pass

        except (socket.gaierror, OSError) as e:
            logger.debug(f"DNS resolution error for {hostname}: {e}")
