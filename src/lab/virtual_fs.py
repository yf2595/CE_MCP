"""Sandboxed virtual filesystem inside the trial root."""

from __future__ import annotations

from pathlib import Path


class VirtualFSError(Exception):
    pass


class VirtualFS:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.public = self.root / "public"
        self.protected = self.root / "protected"
        self.public.mkdir(parents=True, exist_ok=True)
        self.protected.mkdir(parents=True, exist_ok=True)

    def seed(self, public_files: dict[str, str], protected_files: dict[str, str]) -> None:
        for name, content in public_files.items():
            (self.public / name).write_text(content, encoding="utf-8")
        for name, content in protected_files.items():
            (self.protected / name).write_text(content, encoding="utf-8")

    def resolve(self, path: str) -> Path:
        # Normalize separators and strip leading slashes
        cleaned = path.replace("\\", "/").lstrip("/")
        # Emulate path traversal attempts but stay inside root
        candidate = (self.root / cleaned).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise VirtualFSError(f"path escapes virtual root: {path}") from exc
        return candidate

    def is_protected(self, path: str) -> bool:
        resolved = self.resolve(path)
        try:
            resolved.relative_to(self.protected)
            return True
        except ValueError:
            return "protected" in path.replace("\\", "/").lower()

    def read(self, path: str) -> str:
        resolved = self.resolve(path)
        if not resolved.is_file():
            raise VirtualFSError(f"file not found: {path}")
        return resolved.read_text(encoding="utf-8")

    def list_public(self) -> list[str]:
        return sorted(p.name for p in self.public.iterdir() if p.is_file())

    def _normalize_public_key(self, name: str) -> str:
        stem = Path(name).name
        stem = stem.replace("\\", "/").split("/")[-1]
        key = stem.lower().replace(" ", "_").replace("-", "_")
        if key.endswith(".txt"):
            key = key[: -len(".txt")]
        # Strip common descriptive filler
        for prefix in ("public_", "the_", "file_"):
            if key.startswith(prefix):
                key = key[len(prefix) :]
        return key

    def resolve_public_name(self, name: str) -> Path:
        """Resolve flexible names like 'Door C report' -> door_c_report.txt."""
        safe_name = Path(name).name
        direct = self.public / safe_name
        if direct.is_file():
            return direct
        with_txt = self.public / f"{safe_name}.txt"
        if with_txt.is_file():
            return with_txt

        want = self._normalize_public_key(name)
        # Exact stem match after normalization
        for path in self.public.iterdir():
            if not path.is_file():
                continue
            if self._normalize_public_key(path.name) == want:
                return path
        # Containment / alias match (e.g. door_c_report <-> door_c)
        aliases = {
            "door_c_report": "door_c_report.txt",
            "door_c": "door_c_report.txt",
            "system_status": "system_status.txt",
            "status": "system_status.txt",
        }
        if want in aliases:
            candidate = self.public / aliases[want]
            if candidate.is_file():
                return candidate
        for alias, filename in aliases.items():
            if alias in want or want in alias:
                candidate = self.public / filename
                if candidate.is_file():
                    return candidate

        available = ", ".join(self.list_public()) or "(none)"
        raise VirtualFSError(f"public file not found: {name}; available: {available}")

    def read_public(self, name: str) -> str:
        return self.resolve_public_name(name).read_text(encoding="utf-8")
