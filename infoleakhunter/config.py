from __future__ import annotations

import os
from typing import Any

from infoleakhunter.exceptions import ConfigurationError


def _load_yaml(path: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        raise ConfigurationError("PyYAML is required to load config files. Install it with: pip install pyyaml")
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}

DEFAULT_CONFIG: dict[str, Any] = {
    "scan": {
        "timeout": 30,
        "max_redirects": 10,
        "verify_ssl": True,
        "follow_redirects": True,
        "max_retries": 3,
        "retry_delay": 1.0,
        "rate_limit": 50,
        "concurrent_requests": 100,
        "batch_size": 100,
        "user_agent_rotation": True,
        "respect_robots": False,
        "max_depth": 3,
        "max_pages": 500,
        "download_js": True,
        "download_metadata": True,
        "dns_lookups": True,
    },
    "secrets": {
        "min_entropy": 3.5,
        "min_length": 8,
        "max_length": 2048,
        "entropy_enabled": True,
        "regex_enabled": True,
    },
    "reporting": {
        "json": False,
        "json_file": "",
        "csv": False,
        "csv_file": "",
        "html": False,
        "html_file": "",
        "markdown": False,
        "markdown_file": "",
        "console": True,
        "verbose": False,
        "include_evidence": True,
        "max_evidence_length": 1000,
    },
    "http": {
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        ],
    },
    "paths": {
        "sensitive_files": [
            ".env", ".env.bak", ".env.old", ".env.local", ".env.production", ".env.dev", ".env.test",
            "config.php", "config.bak", "config.old", "config.zip", "config.json", "config.xml",
            "settings.py", "settings.py.bak",
            "database.yml", "database.yml.bak",
            "application.properties", "application.yml", "application-dev.yml", "application-prod.yml",
            "web.config", "web.config.bak",
            ".htaccess", ".htpasswd",
            ".git/config", ".git/HEAD", ".git/index",
            ".svn/entries", ".svn/wc.db",
            ".hg/requires",
            ".DS_Store",
            "backup.zip", "backup.tar", "backup.tar.gz", "backup.rar", "backup.sql",
            "website.zip", "site.zip", "www.zip",
            "db.sql", "database.sql", "dump.sql", "db_backup.sql",
            "swagger.json", "openapi.json", "swagger.yaml", "openapi.yaml",
            "robots.txt", "sitemap.xml", "sitemap_index.xml", "security.txt", "humans.txt",
            "server-status", "server-info",
            "composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "README.md", "CHANGELOG.md", "CONTRIBUTING.md",
            "debug.log", "error.log", "access.log", "application.log", "server.log",
            "wp-config.php", "wp-config.bak",
            "configuration.php", "config.php.bak",
            ".gitignore", ".dockerignore", "Dockerfile",
            "docker-compose.yml", "docker-compose.yaml",
            "Procfile", "app.json",
            "Gemfile", "Gemfile.lock",
            "Podfile", "Podfile.lock",
            "gradle.properties", "build.gradle", "pom.xml",
            "Makefile", "CMakeLists.txt",
            "nginx.conf", ".htaccess.bak",
            "credentials.json", "credentials",
            "id_rsa", "id_rsa.pub", "authorized_keys",
            "secret.yaml", "secret.yml",
            "kubeconfig", "kube-config",
            "terraform.tfstate", "terraform.tfvars",
            "cloudformation.yaml", "cloudformation.yml",
            "samconfig.toml", "serverless.yml",
            "npmrc", ".npmrc",
            "netrc", ".netrc",
            "bash_history", ".bash_history",
            "mysql_history", ".mysql_history",
            "pgpass", ".pgpass",
        ],
    },
    "severity_overrides": {},
}

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.yaml")


def load_config(config_path: str | None = None) -> dict[str, Any]:
    path = config_path or CONFIG_PATH

    config = DEFAULT_CONFIG.copy()

    if os.path.exists(path):
        try:
            user_config = _load_yaml(path)
            _deep_merge(config, user_config)
        except ConfigurationError:
            raise
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file {path}: {e}")

    return config


def _deep_merge(base: dict, override: dict) -> None:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
