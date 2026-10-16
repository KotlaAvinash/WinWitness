"""Knowledge about the Capability Access Manager databases.

Every mapping here is tagged with how it was established:
  [measured]  - verified on a Windows 11 25H2 (build 26200) host by comparing the database with
                that host's live HKCU/HKLM ConsentStore registry
  [published] - taken from public research (Cyber Sundae DFIR series, 2024-2025)
  [observed]  - seen in the data, meaning not proven
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
FT_MIN = 116444736000000000            # 1970-01-01
FT_MAX = 159725088000000000            # 2107-02-07 (sanity ceiling)
FT_PLAUSIBLE_LO = 130000000000000000   # 2012-12-14, before Windows 10/11 existed -> suspicious
FT_PLAUSIBLE_HI = 137000000000000000   # 2035-02-13

CAM_DB = "CapabilityAccessManager.db"
CONSENT_DB = "CapabilityConsentStorage.db"

LOOKUP_TABLES = ("Capabilities", "PackageFamilyNames", "BinaryFullPaths", "Users", "FileIDs",
                 "ProgramIDs", "AccessGUIDs", "AppNames", "ServiceNames", "BinaryNames")

# Which lookup table each foreign-key column points at.
FK_MAP = {
    "Capability": "Capabilities", "PackageFamilyName": "PackageFamilyNames",
    "BinaryFullPath": "BinaryFullPaths", "UserSid": "Users", "FileID": "FileIDs",
    "ProgramID": "ProgramIDs", "AccessGUID": "AccessGUIDs", "AppName": "AppNames",
    "ServiceName": "ServiceNames", "BinaryName": "BinaryNames",
}

# Foreign keys that must point at a row (never 0) in every live row seen; used to reject
# misaligned carves.  [observed: 0 occurrences of 0 in 370 live rows]
REQUIRED_FK = ("Capability", "UserSid", "PackageFamilyName", "BinaryFullPath", "FileID", "ProgramID")

TIME_COLUMNS = ("LastUsedTimeStart", "LastUsedTimeStop", "LastObservedTime", "ShownTime")

# CapabilityConsentStorage.db "Value" column  [measured: 34/34 App rows + 2 global rows matched
# HKCU\...\ConsentStore\<cap>\<app>\Value on a build 26200 host, 186/186 values]
CONSENT_VALUE = {1: "Allow", 2: "Deny", 3: "Prompt"}

# AccessBlocked  [published] 0 = access granted, 1 = blocked
ACCESS_BLOCKED = {0: "Allowed", 1: "Blocked"}


def filetime_to_dt(v) -> datetime | None:
    if not isinstance(v, int) or v <= 0:
        return None
    if v < FT_MIN or v > FT_MAX:
        return None
    return EPOCH_1601 + timedelta(microseconds=v // 10)


def fmt_dt(dt: datetime | None, tz: timezone | None = None) -> str:
    if dt is None:
        return ""
    if tz is not None:
        dt = dt.astimezone(tz)
    s = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    return s


def ft_str(v, tz=None) -> str:
    """FILETIME -> 'YYYY-MM-DD HH:MM:SS.ffffff' (UTC unless tz given). Raw 0 -> ''."""
    if v in (0, None):
        return ""
    dt = filetime_to_dt(v)
    return fmt_dt(dt, tz) if dt else f"INVALID({v})"


def parse_tz(s: str | None) -> timezone:
    if not s or s.upper() in ("UTC", "Z", "+00:00"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})", s.strip())
    if not m:
        raise ValueError(f"bad --tz '{s}', use e.g. +05:30")
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


# --------------------------------------------------------------------------- schema signatures
@dataclass
class Column:
    name: str
    decl: str
    pk_alias: bool       # INTEGER PRIMARY KEY -> stored as NULL in the record
    not_null: bool
    has_default: bool
    default: object = None

    @property
    def affinity(self) -> str:
        d = self.decl.upper()
        if "INT" in d:
            return "INTEGER"
        if any(x in d for x in ("CHAR", "CLOB", "TEXT")):
            return "TEXT"
        if "BLOB" in d or not d:
            return "BLOB"
        if any(x in d for x in ("REAL", "FLOA", "DOUB")):
            return "REAL"
        return "NUMERIC"


@dataclass
class TableSig:
    db: str
    table: str
    columns: list
    min_cols: int
    rowid_table: bool = True

    @property
    def max_cols(self) -> int:
        return len(self.columns)

    def allowed(self, i: int) -> set | None:
        """Allowed serial types for column i (None = text any length / int any)."""
        return None

    def check_types(self, types: list) -> bool:
        if not (self.min_cols <= len(types) <= self.max_cols):
            return False
        for c, st in zip(self.columns, types):
            if c.pk_alias:
                if st != 0:
                    return False
                continue
            if st == 0:
                if c.not_null:
                    return False
                continue
            aff = c.affinity
            if aff == "INTEGER":
                if not (1 <= st <= 6 or st in (8, 9)):
                    return False
            elif aff == "TEXT":
                if st < 13 or st % 2 == 0:
                    return False
            elif st in (10, 11):
                return False
        return True

    def plausible(self, values: list) -> bool:
        for c, v in zip(self.columns, values):
            if c.pk_alias or v is None:      # NULL was already checked against NOT NULL in check_types
                continue
            if c.name in TIME_COLUMNS:
                if not isinstance(v, int):
                    return False
                if v != 0 and not (FT_MIN <= v <= FT_MAX):
                    return False
            elif c.affinity == "INTEGER" and isinstance(v, int):
                if v < 0 or v > 0x7FFFFFFF:
                    return False
                if c.name in REQUIRED_FK and v == 0 and self.db.endswith("AccessManager.db"):
                    return False
            elif c.affinity == "TEXT":
                if not isinstance(v, str) or not v or "�" in v:
                    return False
                if any(ord(ch) < 0x20 for ch in v):
                    return False
        return True


_COLDEF = re.compile(r"^\s*\"?(\w+)\"?\s*(.*)$", re.S)


def split_columns(sql: str) -> list[str]:
    body = sql[sql.index("(") + 1: sql.rindex(")")]
    out, depth, cur = [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [c.strip() for c in out if c.strip()]


def sig_from_sql(db: str, table, sql) -> TableSig | None:
    """Build a signature from CREATE TABLE text; None if the text is damaged or not a table."""
    if not isinstance(sql, str) or not isinstance(table, str) or not sql.upper().startswith("CREATE TABLE"):
        return None
    try:
        return _sig_from_sql(db, table, sql)
    except (ValueError, IndexError, AttributeError):
        return None


def _sig_from_sql(db: str, table: str, sql: str) -> TableSig | None:
    cols = []
    table_pk = None
    for part in split_columns(sql):
        up = part.upper()
        if up.startswith(("PRIMARY KEY", "UNIQUE", "CHECK", "FOREIGN KEY", "CONSTRAINT")):
            if up.startswith("PRIMARY KEY"):
                table_pk = [x.strip().strip('"') for x in part[part.index("(") + 1:part.rindex(")")].split(",")]
            continue
        m = _COLDEF.match(part)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        ru = rest.upper()
        decl = rest.split()[0] if rest.split() and rest.split()[0].upper() not in ("PRIMARY", "NOT", "DEFAULT", "COLLATE") else ""
        pk_alias = "PRIMARY KEY" in ru and decl.upper() == "INTEGER" and "DESC" not in ru
        dm = re.search(r"DEFAULT\s+('([^']*)'|(-?\d+(?:\.\d+)?)|NULL)", rest, re.I)
        dflt = None
        if dm:
            raw = dm.group(2) if dm.group(2) is not None else dm.group(3)
            dflt = raw
            if raw is not None and "INT" in decl.upper() and re.fullmatch(r"-?\d+", raw):
                dflt = int(raw)
        cols.append(Column(name, decl, pk_alias, "NOT NULL" in ru or pk_alias, dm is not None, dflt))
    if table_pk and len(table_pk) == 1:
        for c in cols:
            if c.name == table_pk[0] and c.decl.upper() == "INTEGER":
                c.pk_alias = True
    # Trailing columns that are nullable or have a DEFAULT may be absent in rows written before an
    # ALTER TABLE ADD COLUMN; the record is then shorter than the schema.
    min_cols = len(cols)
    while min_cols > 1 and (not cols[min_cols - 1].not_null or cols[min_cols - 1].has_default) \
            and not cols[min_cols - 1].pk_alias:
        min_cols -= 1
    if not cols:
        return None
    return TableSig(db, table, cols, min_cols, "WITHOUT ROWID" not in sql.upper())


# --------------------------------------------------------------------------- lookup classification
_RE_SID = re.compile(r"^S-1-\d+(-\d+)+$", re.I)
_RE_FILEID = re.compile(r"^0000[0-9a-f]{40}$", re.I)
_RE_PROGID = re.compile(r"^000[0-9a-f][0-9a-f]{40}$", re.I)
_RE_PFN = re.compile(r"^[\w.\-]+_[a-z0-9]{13}$", re.I)
_RE_GUID = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I)
_RE_PATH = re.compile(r"^([a-z]:\\|\\\\|\\\?\?\\|%)", re.I)
_RE_EXE = re.compile(r"^[^\\/:]+\.(exe|dll|com|scr|bat|cmd|msi)$", re.I)
_RE_CAP = re.compile(r"^[a-z][A-Za-z.]+$")


def classify_lookup_string(s: str) -> str:
    """Best guess of which lookup table a carved (ID, StringValue) record came from. [observed]"""
    if _RE_SID.match(s):
        return "Users"
    if _RE_FILEID.match(s):
        # Both are 44 hex chars beginning 0000. ProgramIDs on the reference host all end in
        # 0000ffff / 00000904 / 00000000 (58/58); a SHA-1 tail matching that is ~3e-9 likely.
        if s.lower().endswith(("0000ffff", "00000904", "00000000")):
            return "ProgramIDs"
        return "FileIDs"
    if _RE_PROGID.match(s):
        return "ProgramIDs"
    if _RE_GUID.match(s):
        return "AccessGUIDs"
    if _RE_PATH.match(s):
        return "BinaryFullPaths"
    if _RE_EXE.match(s):
        return "BinaryNames"
    if _RE_PFN.match(s):
        return "PackageFamilyNames"
    if _RE_CAP.match(s) and " " not in s:
        return "Capabilities|ServiceNames"
    return "AppNames|ServiceNames"


def sha1_from_fileid(fid: str | None) -> str | None:
    if fid and _RE_FILEID.match(fid):
        return fid[4:].lower()
    return None
