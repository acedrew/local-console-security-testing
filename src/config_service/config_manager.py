"""Configuration file management with versioning."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional
import hashlib

logger = logging.getLogger(__name__)


class ConfigVersion:
    """Represents a configuration version."""

    def __init__(self, version: int, data: dict, timestamp: datetime, hash: str):
        self.version = version
        self.data = data
        self.timestamp = timestamp
        self.hash = hash


class ConfigManager:
    """Manages configuration files with versioning and change tracking."""

    def __init__(self, config_dir: Path):
        """
        Initialize configuration manager.

        Args:
            config_dir: Directory for storing configurations
        """
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.current_config_path = self.config_dir / "current_config.json"
        self.versions_dir = self.config_dir / "versions"
        self.versions_dir.mkdir(exist_ok=True)

        self.audit_log_path = self.config_dir / "audit_log.jsonl"

        logger.info(f"Config Manager initialized: {config_dir}")

    def _calculate_hash(self, data: dict) -> str:
        """Calculate hash of configuration data."""
        # Sort keys for consistent hashing
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def _get_next_version(self) -> int:
        """Get next version number."""
        versions = list(self.versions_dir.glob("v*.json"))
        if not versions:
            return 1

        version_numbers = [
            int(v.stem[1:]) for v in versions
            if v.stem[1:].isdigit()
        ]

        return max(version_numbers) + 1 if version_numbers else 1

    def load_config(self) -> Optional[dict]:
        """
        Load current configuration.

        Returns:
            Configuration dictionary or None if not exists
        """
        if not self.current_config_path.exists():
            logger.warning("No current configuration found")
            return None

        try:
            with open(self.current_config_path, 'r') as f:
                config = json.load(f)

            logger.info("Configuration loaded successfully")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return None

    def save_config(
        self,
        config: dict,
        author: str = "system",
        comment: str = ""
    ) -> int:
        """
        Save configuration with versioning.

        Args:
            config: Configuration dictionary
            author: Author of the change
            comment: Change description

        Returns:
            Version number
        """
        logger.info(f"Saving configuration (author: {author})")

        # Calculate hash
        config_hash = self._calculate_hash(config)

        # Check if configuration changed
        current = self.load_config()
        if current and self._calculate_hash(current) == config_hash:
            logger.info("Configuration unchanged, skipping save")
            return self._get_current_version()

        # Get next version
        version = self._get_next_version()
        timestamp = datetime.utcnow()

        # Save versioned copy
        version_path = self.versions_dir / f"v{version}.json"
        version_data = {
            "version": version,
            "timestamp": timestamp.isoformat(),
            "author": author,
            "comment": comment,
            "hash": config_hash,
            "config": config
        }

        with open(version_path, 'w') as f:
            json.dump(version_data, f, indent=2)

        # Update current config
        with open(self.current_config_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Log to audit trail
        self._log_change(version, author, comment, config_hash)

        logger.info(f"Configuration saved as version {version}")
        return version

    def _log_change(self, version: int, author: str, comment: str, config_hash: str):
        """Log configuration change to audit trail."""
        entry = {
            "version": version,
            "timestamp": datetime.utcnow().isoformat(),
            "author": author,
            "comment": comment,
            "hash": config_hash
        }

        with open(self.audit_log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def get_version(self, version: int) -> Optional[ConfigVersion]:
        """
        Get specific configuration version.

        Args:
            version: Version number

        Returns:
            ConfigVersion object or None
        """
        version_path = self.versions_dir / f"v{version}.json"

        if not version_path.exists():
            logger.warning(f"Version {version} not found")
            return None

        try:
            with open(version_path, 'r') as f:
                data = json.load(f)

            return ConfigVersion(
                version=data["version"],
                data=data["config"],
                timestamp=datetime.fromisoformat(data["timestamp"]),
                hash=data["hash"]
            )
        except Exception as e:
            logger.error(f"Failed to load version {version}: {e}")
            return None

    def _get_current_version(self) -> int:
        """Get current version number."""
        versions = list(self.versions_dir.glob("v*.json"))
        if not versions:
            return 0

        version_numbers = [
            int(v.stem[1:]) for v in versions
            if v.stem[1:].isdigit()
        ]

        return max(version_numbers) if version_numbers else 0

    def list_versions(self) -> List[dict]:
        """
        List all configuration versions.

        Returns:
            List of version information dictionaries
        """
        versions = []

        for version_path in sorted(self.versions_dir.glob("v*.json")):
            try:
                with open(version_path, 'r') as f:
                    data = json.load(f)

                versions.append({
                    "version": data["version"],
                    "timestamp": data["timestamp"],
                    "author": data.get("author", "unknown"),
                    "comment": data.get("comment", ""),
                    "hash": data["hash"]
                })
            except Exception as e:
                logger.error(f"Failed to read version {version_path}: {e}")
                continue

        return sorted(versions, key=lambda x: x["version"], reverse=True)

    def rollback(self, version: int, author: str = "system") -> bool:
        """
        Rollback to a previous configuration version.

        Args:
            version: Version number to rollback to
            author: Author of the rollback

        Returns:
            True if successful
        """
        logger.info(f"Rolling back to version {version}")

        version_obj = self.get_version(version)
        if not version_obj:
            logger.error(f"Version {version} not found")
            return False

        # Save as new version with rollback comment
        self.save_config(
            version_obj.data,
            author=author,
            comment=f"Rollback to version {version}"
        )

        logger.info(f"Rolled back to version {version}")
        return True

    def get_audit_log(self, limit: Optional[int] = None) -> List[dict]:
        """
        Get audit log entries.

        Args:
            limit: Maximum number of entries (None for all)

        Returns:
            List of audit log entries
        """
        if not self.audit_log_path.exists():
            return []

        entries = []
        with open(self.audit_log_path, 'r') as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

        # Sort by timestamp (newest first)
        entries.sort(key=lambda x: x["timestamp"], reverse=True)

        if limit:
            entries = entries[:limit]

        return entries

    def diff_versions(self, version1: int, version2: int) -> dict:
        """
        Compare two configuration versions.

        Args:
            version1: First version number
            version2: Second version number

        Returns:
            Dictionary with differences
        """
        v1 = self.get_version(version1)
        v2 = self.get_version(version2)

        if not v1 or not v2:
            raise ValueError("One or both versions not found")

        # Simple diff - could be enhanced with deep comparison
        return {
            "version1": version1,
            "version2": version2,
            "hash_changed": v1.hash != v2.hash,
            "data1": v1.data,
            "data2": v2.data
        }

    def export_config(self, version: Optional[int] = None) -> dict:
        """
        Export configuration for backup.

        Args:
            version: Specific version to export (None for current)

        Returns:
            Configuration data with metadata
        """
        if version:
            version_obj = self.get_version(version)
            if not version_obj:
                raise ValueError(f"Version {version} not found")
            config = version_obj.data
        else:
            config = self.load_config()
            if not config:
                raise ValueError("No current configuration")

        return {
            "version": version or self._get_current_version(),
            "timestamp": datetime.utcnow().isoformat(),
            "config": config
        }

    def import_config(self, data: dict, author: str = "import") -> int:
        """
        Import configuration from backup.

        Args:
            data: Configuration data with metadata
            author: Author of the import

        Returns:
            New version number
        """
        config = data.get("config")
        if not config:
            raise ValueError("Invalid import data: missing config")

        return self.save_config(
            config,
            author=author,
            comment=f"Imported from version {data.get('version', 'unknown')}"
        )

    def get_version_history(self) -> List[dict]:
        """Alias for list_versions() - for compatibility."""
        return self.list_versions()

    def restore_version(self, version: int, author: str = "system") -> bool:
        """Alias for rollback() - for compatibility."""
        return self.rollback(version, author)
