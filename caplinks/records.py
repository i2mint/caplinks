"""Link records as JSON text in a store of text: a mapping from token to dict.

:class:`CapabilityLinks` keeps its records in any ``MutableMapping`` of token to dict.
:class:`JsonRecords` makes one from a mapping of *text* (``<token>.json`` to the JSON of
the record), and :class:`FileTexts` is that text mapping over a local folder, written
atomically and readable by the owner only (a record holds a password hash). A host whose
text lives elsewhere (ssh, S3) passes its own mapping of text.

>>> import tempfile
>>> from caplinks import CapabilityLinks
>>> links = CapabilityLinks(JsonRecords(FileTexts(tempfile.mkdtemp())))
>>> token = links.create({"doc": "d1"})["token"]
>>> links.status(token)[1]["doc"]
'd1'
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterator, MutableMapping
from pathlib import Path

from caplinks.links import TOKEN_RE, check_token

SUFFIX = ".json"


class JsonRecords(MutableMapping):
    """``{token: dict}`` over a mapping of text, ``<token>.json`` to its JSON.

    A record that cannot be read, is not a JSON object, or fails ``valid`` raises
    ``KeyError``: the link is then missing (every failure closes the link). ``valid``
    takes the host's own check of its fields. ``deletable=False`` refuses ``del``: a
    host that keeps a revoked link as a tombstone says so. ``indent`` pretty-prints.

    The contract of ``texts``: reading a missing name raises ``KeyError``.
    """

    def __init__(
        self,
        texts: MutableMapping[str, str],
        *,
        valid: Callable[[dict], bool] | None = None,
        deletable: bool = True,
        indent: int | None = None,
    ):
        self.texts = texts
        self.valid = valid
        self.deletable = deletable
        self.indent = indent

    @staticmethod
    def _name(token: str) -> str:
        try:
            return check_token(token) + SUFFIX
        except ValueError:
            raise KeyError(token) from None

    def __getitem__(self, token: str) -> dict:
        try:
            rec = json.loads(self.texts[self._name(token)])
        except (ValueError, KeyError, OSError, RuntimeError, TypeError):
            raise KeyError(token) from None
        if not isinstance(rec, dict) or (self.valid and not self.valid(rec)):
            raise KeyError(token)
        return rec

    def __setitem__(self, token: str, record: dict) -> None:
        self.texts[self._name(token)] = json.dumps(record, indent=self.indent)

    def __delitem__(self, token: str) -> None:
        if not self.deletable:
            raise TypeError("link records are never deleted; revoke the link instead")
        del self.texts[self._name(token)]

    def __iter__(self) -> Iterator[str]:
        for name in self.texts:
            token = name[: -len(SUFFIX)]
            if name.endswith(SUFFIX) and TOKEN_RE.match(token):
                yield token

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, token) -> bool:
        try:
            return self._name(token) in self.texts
        except (KeyError, TypeError):
            return False


class FileTexts(MutableMapping):
    """``{name: text}`` over the files of one local folder (created on first write).

    Names are plain file names (no path separator, no leading dot, no NUL); a name whose
    file is a symlink out of the folder is missing. The folder is private (mode 0700:
    the names are link tokens) and a write goes to a hidden temporary file (mode 0600)
    that replaces the target, so a reader never sees half a record.
    """

    def __init__(self, folder: str | os.PathLike):
        self.folder = Path(folder).expanduser()

    def _path(self, name: str) -> Path:
        if (
            not isinstance(name, str)
            or not name
            or name.startswith(".")
            or any(c in name for c in "/\\\0")
        ):
            raise KeyError(name)
        path = self.folder / name
        if path.is_symlink():
            raise KeyError(name)
        return path

    def __getitem__(self, name: str) -> str:
        try:
            return self._path(name).read_text(encoding="utf-8")
        except (FileNotFoundError, IsADirectoryError):
            raise KeyError(name) from None

    def __setitem__(self, name: str, text: str) -> None:
        path = self._path(name)
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.folder, prefix=".", suffix=".tmp")  # 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def __delitem__(self, name: str) -> None:
        try:
            self._path(name).unlink()
        except FileNotFoundError:
            raise KeyError(name) from None

    def __iter__(self) -> Iterator[str]:
        if self.folder.is_dir():
            for p in self.folder.iterdir():
                if p.is_file() and not p.is_symlink() and not p.name.startswith("."):
                    yield p.name

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, name) -> bool:
        try:
            return self._path(name).is_file()
        except (KeyError, TypeError):
            return False
