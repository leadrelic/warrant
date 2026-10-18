"""Parameter definitions and validation. Nothing user-supplied reaches an argv without passing here."""

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .scope import TargetError, parse_target


class ValidationError(ValueError):
    pass


PORTS_RE = re.compile(r"^(?:[TU]:)?\d{1,5}(?:-\d{1,5})?(?:,(?:[TU]:)?\d{1,5}(?:-\d{1,5})?)*$")
TEXT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.,:/@+=*%\-]{0,199}$")


@dataclass
class Param:
    name: str
    kind: str                  # target | url | text | int | choice | ports | file | flags | bool
    label: str = ""
    required: bool = True
    default: Any = None
    choices: Optional[List[str]] = None
    min: Optional[int] = None
    max: Optional[int] = None
    help: str = ""
    pattern: Optional[str] = None          # for kind=text
    allowed: Optional[Dict[str, Optional[str]]] = None   # for kind=flags: flag -> value regex (None = no value)

    def to_dict(self):
        return {"name": self.name, "kind": self.kind, "label": self.label or self.name, "required": self.required,
                "default": self.default, "choices": self.choices, "min": self.min, "max": self.max,
                "help": self.help, "allowed_flags": sorted(self.allowed) if self.allowed else None}


def validate_params(params: List[Param], raw: Dict[str, Any]):
    """Return (clean_values, targets). Raises ValidationError / TargetError-wrapped errors."""
    raw = dict(raw or {})
    known = {p.name for p in params}
    unknown = set(raw) - known
    if unknown:
        raise ValidationError("unknown parameter(s): " + ", ".join(sorted(unknown)))
    clean, targets = {}, []
    for p in params:
        v = raw.get(p.name)
        if v is None or v == "":
            if p.required and p.default is None:
                raise ValidationError(f"'{p.name}' is required")
            v = p.default
            if v is None:
                continue
        clean[p.name] = _check(p, v, targets)
    return clean, targets


def _check(p: Param, v, targets):
    k = p.kind
    try:
        if k == "target":
            s = str(v).strip()
            parse_target(s)
            targets.append(s)
            return s
        if k == "url":
            s = str(v).strip()
            if not re.match(r"^https?://", s, re.I):
                raise ValidationError(f"'{p.name}' must be an http:// or https:// URL")
            parse_target(s)
            targets.append(s)
            return s
    except TargetError as e:
        raise ValidationError(f"'{p.name}': {e}") from None
    if k == "text":
        s = str(v).strip()
        rx = re.compile(p.pattern) if p.pattern else TEXT_RE
        if not rx.match(s):
            raise ValidationError(f"'{p.name}' has an invalid value")
        return s
    if k == "int":
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValidationError(f"'{p.name}' must be an integer") from None
        if (p.min is not None and n < p.min) or (p.max is not None and n > p.max):
            raise ValidationError(f"'{p.name}' must be between {p.min} and {p.max}")
        return n
    if k == "choice":
        s = str(v)
        if s not in (p.choices or []):
            raise ValidationError(f"'{p.name}' must be one of: {', '.join(p.choices or [])}")
        return s
    if k == "bool":
        if isinstance(v, bool):
            return v
        return str(v).lower() in ("1", "true", "yes", "on")
    if k == "ports":
        s = str(v).replace(" ", "")
        if not PORTS_RE.match(s) or any(int(n) > 65535 for n in re.findall(r"\d+", s)):
            raise ValidationError(f"'{p.name}' is not a valid port list (e.g. 22,80,443 or 1-1024)")
        return s
    if k == "file":
        path = Path(str(v)).expanduser()
        try:
            path = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise ValidationError(f"'{p.name}': file not found: {v}") from None
        if not path.is_file():
            raise ValidationError(f"'{p.name}': not a regular file: {v}")
        return str(path)
    if k == "flags":
        return parse_flags(p, str(v))
    raise ValidationError(f"unsupported parameter kind {k!r}")


def parse_flags(p: Param, text: str) -> List[str]:
    """Allow-list parser for 'extra flags' fields: only known flags with well-formed values pass."""
    try:
        tokens = shlex.split(text)
    except ValueError as e:
        raise ValidationError(f"'{p.name}': {e}") from None
    allowed = p.allowed or {}
    out, i = [], 0
    while i < len(tokens):
        tok = tokens[i]
        flag, eq, val = tok.partition("=")
        if "-T" in allowed and re.fullmatch(r"-T[0-5]", tok):
            out.append(tok)
            i += 1
            continue
        if flag not in allowed:
            raise ValidationError(f"'{p.name}': flag {tok!r} is not allowed")
        key = flag
        rx = allowed[key]
        if rx is None:
            if eq:
                raise ValidationError(f"'{p.name}': {key} takes no value")
            out.append(tok)
            i += 1
            continue
        if not eq:
            i += 1
            if i >= len(tokens):
                raise ValidationError(f"'{p.name}': {key} needs a value")
            val = tokens[i]
        if not re.fullmatch(rx, val):
            raise ValidationError(f"'{p.name}': bad value for {key}: {val!r}")
        out.extend([key, val])
        i += 1
    return out
