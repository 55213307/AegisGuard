import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class ScanFile(BaseModel):
    """One file or folder the scan agent found worth reporting (the agent leaves out what no rule looks at)."""

    path: str = Field(max_length=520)  # relative to the drive for a USB scan, the full path for Downloads
    is_dir: bool = False
    size: int = Field(default=0, ge=0)
    hidden: bool = False
    sha256: str | None = None  # of programs, scripts, shortcuts, libraries, archives and documents
    target: str | None = Field(default=None, max_length=500)  # a .lnk's target and arguments; an autorun.inf's open= lines
    target_signed: bool | None = None  # autorun.inf only: are the programs it starts validly signed?

    @field_validator("sha256")
    @classmethod
    def _hash(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not _SHA256.match(value):
            raise ValueError("sha256 must be 64 hexadecimal characters")
        return value.lower()


class ScanUpload(BaseModel):
    """What the scan agent on a computer reports: a USB drive that was plugged in, or new files in a
    Downloads folder. Only names, attributes and hashes; no file content leaves the computer."""

    scan_id: str = Field(min_length=8, max_length=64)  # one per scan, so a retried upload is not stored twice
    kind: Literal["usb", "download"]
    source: str = Field(max_length=200)  # "E: (MYUSB)" or the Downloads folder
    total: int = Field(default=0, ge=0)  # how many files the drive holds in all (files is only the part that matters)
    files: list[ScanFile] = Field(max_length=5000)


class ProcessRecord(BaseModel):
    """A process the scan agent tried to end."""

    name: str = Field(max_length=120)
    pid: int = Field(ge=0)
    command_line: str | None = Field(default=None, max_length=300)
    error: str | None = Field(default=None, max_length=200)  # why it could not be ended


class ContainmentReport(BaseModel):
    """What the scan agent did after the portal reported a Critical finding: the processes it ended
    (those running from the USB drive or the flagged download) and the ones it could not end."""

    scan_id: str = Field(min_length=8, max_length=64)  # the scan that caused it
    source: str = Field(max_length=200)  # "E: (MYUSB)" or "Downloads"
    ended: list[ProcessRecord] = Field(default=[], max_length=200)
    failed: list[ProcessRecord] = Field(default=[], max_length=200)


class ScanResult(BaseModel):
    findings: int
    locked: bool
    # A finding was Critical (a file on a known-bad list): the agent ends the processes that run from the
    # drive (a USB scan) or from the flagged files (a Downloads scan), whether or not the computer was
    # already locked: a lock does not stop a script that is already running.
    contain: bool = False
    contain_paths: list[str] = []
