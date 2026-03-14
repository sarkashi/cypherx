#!/usr/bin/env python3

import os
import re
import sys
import platform
import hashlib


class SecurityGuard:
    SHELL_CHARS = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r", "\x00", "'", "\""]
    SAFE_IP     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
    SAFE_CIDR   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
    SAFE_DOM    = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    SAFE_EMAIL  = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$")
    SAFE_USER   = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")

    @classmethod
    def sanitize(cls, value: str, field: str = "input") -> str:
        if not isinstance(value, str):
            raise ValueError(f"[CypherX] {field} must be a string")
        value = value.strip()
        for ch in cls.SHELL_CHARS:
            if ch in value:
                raise ValueError(f"[CypherX] Unsafe character detected in {field}: {repr(ch)}")
        if len(value) > 512:
            raise ValueError(f"[CypherX] {field} exceeds maximum length")
        if not value:
            raise ValueError(f"[CypherX] {field} cannot be empty")
        return value

    @classmethod
    def validate_ip(cls, ip: str) -> bool:
        if not cls.SAFE_IP.match(ip.strip()):
            return False
        parts = ip.split("/")[0].split(".")
        return all(0 <= int(p) <= 255 for p in parts)

    @classmethod
    def validate_cidr(cls, cidr: str) -> bool:
        if "/" not in cidr:
            return cls.validate_ip(cidr)
        ip, prefix = cidr.split("/")
        return cls.validate_ip(ip) and 0 <= int(prefix) <= 32

    @classmethod
    def validate_domain(cls, domain: str) -> bool:
        return bool(cls.SAFE_DOM.match(domain.strip()))

    @classmethod
    def validate_email(cls, email: str) -> bool:
        return bool(cls.SAFE_EMAIL.match(email.strip()))

    @classmethod
    def validate_username(cls, username: str) -> bool:
        return bool(cls.SAFE_USER.match(username.strip()))

    @classmethod
    def validate_path(cls, path: str) -> bool:
        if ".." in path:
            return False
        dangerous = ["/etc/shadow", "/etc/passwd", "/proc/", "/sys/", "/dev/"]
        for d in dangerous:
            if path.startswith(d):
                return False
        return True

    @classmethod
    def validate_port_range(cls, ports: str) -> bool:
        try:
            for part in ports.split(","):
                part = part.strip()
                if "-" in part:
                    s, e = part.split("-")
                    if not (1 <= int(s) <= 65535 and 1 <= int(e) <= 65535 and int(s) <= int(e)):
                        return False
                else:
                    if not 1 <= int(part) <= 65535:
                        return False
            return True
        except Exception:
            return False

    @classmethod
    def hash_file(cls, path: str) -> dict:
        h = {"md5": "", "sha1": "", "sha256": ""}
        if not os.path.exists(path):
            return h
        try:
            md5    = hashlib.md5()
            sha1   = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            h["md5"]    = md5.hexdigest()
            h["sha1"]   = sha1.hexdigest()
            h["sha256"] = sha256.hexdigest()
        except Exception:
            pass
        return h

    @classmethod
    def is_root(cls) -> bool:
        if platform.system() == "Windows":
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return os.geteuid() == 0

    @classmethod
    def is_linux(cls) -> bool:
        return platform.system() == "Linux"

    @classmethod
    def is_windows(cls) -> bool:
        return platform.system() == "Windows"


guard = SecurityGuard()
