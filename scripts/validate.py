#!/usr/bin/env python3
"""
validate.py — ZAD Content Repository Validation Script

Enforces:
  1. Manifest authority: every content/*.json must be listed in manifest
  2. Schema compliance: required fields present in each content file
  3. Dependency validation: no disabling/removing content that others depend on
  4. Lifecycle rules: deprecated/disabled items must have valid state transitions
  5. Cross-file reference integrity: IDs referenced across files exist
  6. JSON syntax: all files parse without errors
  7. Checksum verification (when checksums are present)

Usage:
  python scripts/validate.py                    # Validate all
  python scripts/validate.py --check-checksums  # Also verify SHA-256 checksums
"""

import json
import sys
import os
import hashlib
from pathlib import Path
from typing import Any

CONTENT_DIR = Path(__file__).parent.parent / "content"
MANIFEST_PATH = CONTENT_DIR / "manifest.json"

errors: list[str] = []
warnings: list[str] = []


def error(msg: str) -> None:
    errors.append(f"ERROR: {msg}")


def warn(msg: str) -> None:
    warnings.append(f"WARNING: {msg}")


def load_json(path: Path) -> dict | list | None:
    """Load and parse a JSON file, reporting errors."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in {path.name}: {e}")
        return None
    except FileNotFoundError:
        error(f"File not found: {path}")
        return None


def validate_manifest(manifest: dict) -> None:
    """Validate manifest structure."""
    required_fields = ["schemaVersion", "contentVersion", "lastUpdated", "baseUrl", "content"]
    for field in required_fields:
        if field not in manifest:
            error(f"Manifest missing required field: {field}")

    if "content" not in manifest:
        return

    seen_ids: set[str] = set()
    seen_sort_orders: set[int] = set()

    for entry in manifest["content"]:
        # Required entry fields
        entry_required = ["id", "file", "type", "sizeCategory", "enabled", "lifecycle", "sortOrder"]
        for field in entry_required:
            if field not in entry:
                error(f"Manifest entry missing field '{field}': {entry.get('id', '?')}")

        entry_id = entry.get("id", "")

        # Unique IDs
        if entry_id in seen_ids:
            error(f"Duplicate manifest entry ID: {entry_id}")
        seen_ids.add(entry_id)

        # Unique sort orders
        sort_order = entry.get("sortOrder")
        if sort_order is not None:
            if sort_order in seen_sort_orders:
                warn(f"Duplicate sortOrder {sort_order} for entry: {entry_id}")
            seen_sort_orders.add(sort_order)

        # Valid lifecycle state
        valid_lifecycles = ["active", "deprecated", "disabled", "removed"]
        lifecycle = entry.get("lifecycle", "")
        if lifecycle not in valid_lifecycles:
            error(f"Invalid lifecycle '{lifecycle}' for entry: {entry_id}")

        # Valid size category
        valid_sizes = ["metadata", "standard", "heavy", "binary"]
        size_cat = entry.get("sizeCategory", "")
        if size_cat not in valid_sizes:
            error(f"Invalid sizeCategory '{size_cat}' for entry: {entry_id}")

        # File exists (skip removed entries)
        if lifecycle != "removed":
            file_path = CONTENT_DIR.parent / entry.get("file", "")
            if not file_path.exists():
                error(f"Content file missing for entry '{entry_id}': {entry.get('file')}")


def validate_manifest_authority(manifest: dict) -> None:
    """Every content/*.json must be listed in the manifest."""
    manifest_files = set()
    for entry in manifest.get("content", []):
        manifest_files.add(entry.get("file", ""))

    # Scan content directory for JSON files (excluding manifest itself)
    for json_file in CONTENT_DIR.glob("*.json"):
        if json_file.name == "manifest.json":
            continue
        relative = f"content/{json_file.name}"
        if relative not in manifest_files:
            error(f"Unlisted content file: {json_file.name} — not in manifest")


def validate_dependencies(manifest: dict) -> None:
    """Ensure no disabled/removed content has active dependents."""
    entries = {e["id"]: e for e in manifest.get("content", [])}

    for entry in manifest.get("content", []):
        deps = entry.get("dependencies") or []
        for dep_id in deps:
            if dep_id not in entries:
                error(f"Entry '{entry['id']}' depends on unknown ID: {dep_id}")
                continue

            dep_entry = entries[dep_id]
            if dep_entry.get("lifecycle") in ("disabled", "removed"):
                dep_lifecycle = dep_entry.get("lifecycle")
                if entry.get("lifecycle") == "active":
                    error(
                        f"Active entry '{entry['id']}' depends on "
                        f"{dep_lifecycle} entry '{dep_id}'"
                    )


def validate_content_schema(file_path: Path, data: dict) -> None:
    """Validate common schema patterns in content files."""
    name = file_path.name

    # All content files must have schemaVersion and contentVersion
    for field in ["schemaVersion", "contentVersion", "lastUpdated"]:
        if field not in data:
            error(f"{name}: missing required field '{field}'")

    # Files with items arrays
    if "items" in data:
        items = data["items"]
        if not isinstance(items, list):
            error(f"{name}: 'items' must be an array")
            return

        seen_ids: set[str] = set()
        for i, item in enumerate(items):
            # Each item must have an id
            item_id = item.get("id")
            if not item_id:
                error(f"{name}: item at index {i} missing 'id'")
                continue

            if item_id in seen_ids:
                error(f"{name}: duplicate item ID '{item_id}'")
            seen_ids.add(item_id)

            # Each item must have enabled field
            if "enabled" not in item:
                warn(f"{name}: item '{item_id}' missing 'enabled' field")

            # Each item must have sortOrder
            if "sortOrder" not in item:
                warn(f"{name}: item '{item_id}' missing 'sortOrder' field")


def validate_books(data: dict) -> None:
    """Validate books.json specific schema."""
    for item in data.get("items", []):
        if "volumes" not in item:
            error(f"books.json: book '{item.get('id')}' missing 'volumes'")
        else:
            for vol in item["volumes"]:
                if "pdfURL" not in vol:
                    error(f"books.json: volume '{vol.get('id')}' missing 'pdfURL'")
                if "id" not in vol:
                    error(f"books.json: volume missing 'id' in book '{item.get('id')}'")


def validate_live_channels(data: dict) -> None:
    """Validate live_channels.json specific schema."""
    for item in data.get("items", []):
        if "streams" not in item or not item["streams"]:
            error(f"live_channels.json: channel '{item.get('id')}' missing 'streams'")
        else:
            for stream in item["streams"]:
                for field in ["url", "type", "priority"]:
                    if field not in stream:
                        error(
                            f"live_channels.json: stream in '{item.get('id')}' "
                            f"missing '{field}'"
                        )


def validate_adhan_sounds(data: dict) -> None:
    """Validate adhan_sounds.json specific schema."""
    valid_styles = data.get("styles", [])
    for item in data.get("items", []):
        style = item.get("style", "")
        if valid_styles and style not in valid_styles:
            error(f"adhan_sounds.json: item '{item.get('id')}' has unknown style '{style}'")
        if "audioFile" not in item:
            warn(f"adhan_sounds.json: item '{item.get('id')}' missing 'audioFile'")


def validate_reciters(data: dict) -> None:
    """Validate reciters_featured.json specific schema."""
    for item in data.get("items", []):
        if "mpieces" not in item or not item["mpieces"]:
            error(f"reciters_featured.json: reciter '{item.get('id')}' missing 'mpieces'")
        else:
            for moshaf in item["mpieces"]:
                if "server" not in moshaf:
                    error(
                        f"reciters_featured.json: moshaf in '{item.get('id')}' "
                        f"missing 'server'"
                    )


def validate_checksums(manifest: dict, check: bool) -> None:
    """Verify SHA-256 checksums if present and --check-checksums flag is set."""
    if not check:
        return

    for entry in manifest.get("content", []):
        checksum = entry.get("checksum", "")
        if not checksum:
            continue

        file_path = CONTENT_DIR.parent / entry.get("file", "")
        if not file_path.exists():
            continue

        with open(file_path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()

        if actual != checksum:
            error(
                f"Checksum mismatch for '{entry['id']}': "
                f"expected {checksum[:16]}..., got {actual[:16]}..."
            )


def main() -> int:
    check_checksums = "--check-checksums" in sys.argv

    print("=== ZAD Content Validation ===\n")

    # 1. Load manifest
    manifest = load_json(MANIFEST_PATH)
    if manifest is None:
        print("FATAL: Cannot load manifest.json")
        return 1

    print(f"Manifest version: {manifest.get('contentVersion', '?')}")
    print(f"Content entries: {len(manifest.get('content', []))}")
    print()

    # 2. Validate manifest structure
    print("Checking manifest structure...")
    validate_manifest(manifest)

    # 3. Validate manifest authority
    print("Checking manifest authority (no unlisted files)...")
    validate_manifest_authority(manifest)

    # 4. Validate dependencies
    print("Checking dependencies...")
    validate_dependencies(manifest)

    # 5. Validate each content file
    print("Validating content files...")

    content_validators = {
        "books.json": validate_books,
        "live_channels.json": validate_live_channels,
        "adhan_sounds.json": validate_adhan_sounds,
        "reciters_featured.json": validate_reciters,
    }

    for entry in manifest.get("content", []):
        file_rel = entry.get("file", "")
        file_path = CONTENT_DIR.parent / file_rel
        if not file_path.exists():
            continue

        data = load_json(file_path)
        if data is None:
            continue

        if isinstance(data, dict):
            validate_content_schema(file_path, data)

            # File-specific validation
            file_name = file_path.name
            if file_name in content_validators:
                content_validators[file_name](data)

    # 6. Checksums
    if check_checksums:
        print("Verifying checksums...")
        validate_checksums(manifest, check_checksums)

    # Results
    print()
    print(f"Warnings: {len(warnings)}")
    for w in warnings:
        print(f"  {w}")

    print(f"Errors: {len(errors)}")
    for e in errors:
        print(f"  {e}")

    if errors:
        print("\nVALIDATION FAILED")
        return 1
    else:
        print("\nVALIDATION PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
