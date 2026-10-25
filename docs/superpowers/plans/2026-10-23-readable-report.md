# WinWitness v2 Readable Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn WinWitness's output into an analyst-first report: who used which feature, when, for how long, allowed or not, in time order, with app/feature/permission/program views, offline registry hives and an Excel export.

**Architecture:** The engine (sqlite_low, carver, engine, corroborate) stays as is. Three new modules sit between the engine and the report:
* `regf.py`: offline hive reader
* `views.py`: analyst views built from the decoded data
* `xlsx.py`: stdlib Excel writer

`report.py` gains `write_html_v2`. `cli.py` wires hives in automatically and writes the new outputs.

**Tech Stack:** Python 3.10+ standard library only. Tests use `unittest` via `python -I tests/run_tests.py`.

**Spec:** `docs/superpowers/specs/2026-10-23-readable-report-design.md`

## Amendments agreed with the user (2026-10-23, supersede the tasks below where they conflict)
- **The DBs are the primary input. Hives are optional.** `NTUSER.DAT` and `SOFTWARE` are used only when present, and a missing hive is never an error.
- **Columns** the activity timeline must carry:
  - date, start, end, duration
  - application (friendly name + id)
  - service, plus a one-line plain description of that service
  - account (SID, or `name (SID)` when SOFTWARE ProfileList is present)
  - Allowed/Blocked
  - "who allowed it": the current consent setting for that account and app, and the level that decided it (App / User default / System default / Desktop-apps switch)
  - use number per app×service (`#3 of 12`)
  - application location (exe path; Store apps get a derived `C:\Program Files\WindowsApps\<package>_*`, marked derived)
  - installer location
- **Installer:**
  - Only from SOFTWARE `Microsoft\Windows\CurrentVersion\Uninstall\*` and `WOW6432Node\…\Uninstall\*`: match the exe path against `InstallLocation`/`DisplayIcon`, then show `InstallSource`, Publisher, DisplayVersion and InstallDate.
  - With no SOFTWARE hive, show "not recorded in CAM".
- **NTUSER key last-write:** when it is after a use, flag "setting changed after this use".
- **UI:** a designed, engaging dashboard, not a table dump:
  - hero summary with key numbers
  - service tiles with icons and counts
  - a day/hour activity chart
  - per-app cards
  - colour-coded service and status badges
  - a readable timeline grouped by day with expandable detail
  - light and dark themes

## Global Constraints
- Standard library only; no new dependencies.
- Inputs are opened read-only; integrity re-hash still runs; exit codes 0/1/2/3 unchanged.
- The existing 38 tests must still pass. Output must be deterministic for the same input.
- Never guess. A purged lookup is shown as `unknown <kind> (purged, ID n)`.
- Times: UTC always, plus the `--tz` local column. Format `YYYY-MM-DD HH:MM:SS`, with milliseconds only in detail views.
- No personal data in committed tests or fixtures.

## Review Focus
- Evidence with only CapabilityAccessManager.db (no consent DB, no hives): every view still builds, and the permission view says "no consent data". *(test in Task 3)*
- A file named NTUSER.DAT that is not a hive, or is truncated: skip it with a log line, no crash. *(test in Task 1)*
- A purged lookup ID in a recovered row: the app shows as `unknown app (purged, ID 28)`. *(test in Task 3)*
- 50,000 activity rows: the HTML must still open. JS renders in pages of 500, with filters over the full data. *(test in Task 5)*
- The same event in both the DB and the registry: it appears once, with source `Database + Registry`. *(test in Task 3)*

---

### Task 1: Offline registry hive reader

**Files:**
- Create: `winwitness/regf.py`
- Create: `tests/hivegen.py` (writes a minimal valid regf hive)
- Test: `tests/test_regf.py`

**Interfaces:**
- Produces:
  - `Hive(data: bytes)`, raising `RegfError` when the data is not a regf hive
  - `Hive.key(path: str) -> Key | None` (case-insensitive, `\`-separated, relative to the root)
  - `Key.name: str`, `Key.last_write_utc: str`, `Key.subkeys() -> list[Key]`, `Key.values() -> dict[str, object]`
  - Value decoding: REG_SZ/EXPAND_SZ → str, DWORD → int, QWORD → int, BINARY → bytes, MULTI_SZ → list[str]

- [ ] **Step 1: Write the failing tests.**
  * `test_generated_hive_roundtrip`: `hivegen.build({"A\\B": {"Value": "Allow", "LastUsedTimeStart": ("qword", 134365667394199327)}})` → `Hive(b).key("A\\B").values() == {"Value": "Allow", "LastUsedTimeStart": 134365667394199327}`.
  * `test_many_subkeys_lf_and_ri`: 600 subkeys; all enumerated.
  * `test_not_a_hive`: `Hive(b"MZ"*100)` raises `RegfError`.
  * `test_truncated_hive_no_crash`: the first 5000 bytes of a generated hive give `key()` → None or a Key, never another exception.
  * `test_default_profile_hive` (skipped if `C:\Users\Default\NTUSER.DAT` is unreadable): the root has more than 5 subkeys, and `key("Control Panel")` is not None.
- [ ] **Step 2:** Run `python -I tests/run_tests.py -k regf` → FAIL (module missing).
- [ ] **Step 3: Implement `winwitness/regf.py`.**
  * Base block: `regf` signature; root cell offset at 0x24; hbins at 0x1000; cell offsets are relative to 0x1000.
  * nk record layout:
    * flags u16 @2
    * FILETIME @4
    * subkey count u32 @0x14
    * subkey list @0x1C
    * value count @0x24
    * value list @0x28
    * name length u16 @0x48
    * name @0x4C (ASCII if flags & 0x20, else UTF-16LE)
  * Subkey lists: `lf`/`lh`, `li`, `ri`.
  * vk record layout:
    * name length @2
    * data size @4 (high bit set means the data is inline in the offset field)
    * data offset @8
    * type @0xC
    * flags @0x10 (bit 0 means the name is ASCII)
    * name @0x14
  * Data above 16,344 bytes uses `db` big-data segments.
  * Every offset is bounds-checked and a visited set guards against loops.
- [ ] **Step 4:** Run `python -I tests/run_tests.py -k regf` → PASS.
- [ ] **Step 5:** Commit `feat: offline registry hive reader`.

### Task 2: Registry hives as evidence

**Files:**
- Modify: `winwitness/corroborate.py` (add `read_hive_consentstore`, `read_software_hive`)
- Modify: `winwitness/engine.py` `discover()`: roles `NTUSER.DAT` (may be several, keyed `NTUSER.DAT:<relative path>`) and `SOFTWARE`
- Modify: `winwitness/cli.py`: when hives are present, use them as `reg` without needing `--registry`
- Test: `tests/test_regf.py`

**Interfaces:**
- Consumes: `Hive` (Task 1)
- Produces:
  * `read_hive_consentstore(hive: Hive, label: str) -> dict`. It has the same shape as `read_live_registry()`: `{"source", "entries": [{"hive","capability","app","nonpackaged","Value","LastUsedTimeStart","LastUsedTimeStop","key_last_write"}], "sid": None}`.
  * `read_software_hive(hive: Hive) -> dict`: `{"os": {"product","display_version","build","ubr"}, "profiles": {sid: profile_path}, "usage_history_settings": {...}, "consent_entries": [...]}`.

- [ ] **Step 1: Write the failing tests.**
  * `test_consentstore_from_hive`: a generated hive with `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#x#a.exe` holding Value=Deny and a LastUsedTimeStart QWORD. Expect an entry with `app == r"C:\x\a.exe"`, `nonpackaged=True`, `Value == "Deny"`.
  * `test_software_profiles`: `Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1-2-3-1001` with ProfileImagePath `C:\Users\alice` gives `profiles == {"S-1-5-21-1-2-3-1001": r"C:\Users\alice"}`.
  * `test_discover_finds_hives`: a folder with `NTUSER.DAT` and `SOFTWARE` gives both roles.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. The CLI merges every NTUSER entry list into one `reg` dict. If `--registry` is also given, both sets of entries are kept, each with its `source`.
- [ ] **Step 4:** Run `-k regf` and the full suite → PASS.
- [ ] **Step 5:** Commit `feat: read ConsentStore and ProfileList from offline hives`.

### Task 3: Analyst views

**Files:**
- Create: `winwitness/views.py`
- Test: `tests/test_views.py`

**Interfaces:**
- Consumes: `corroborate.decode_cam()` output (`usage`, `carved_usage`, `prompts`, `identity`, `lookups`), `decode_consent()` output, `reg` dict (Task 2 or live), `DbAnalysis.wal_changes`.
- Produces:
  * `feature_label(cap: str) -> str`. Mappings:
    * webcam → Camera
    * microphone → Microphone
    * location → Location
    * contacts → Contacts
    * graphicsCaptureWithoutBorder → Screen capture (no border)
    * graphicsCaptureProgrammatic → Screen capture (programmatic)
    * passkeys → Passkey use
    * passkeysEnumeration → Passkey list
    * unknown names fall back to themselves
  * `app_label(app_id: str, app_name: str = "") -> str`. Order of preference:
    1. AppName if given
    2. the known table (≥ 25 common Microsoft/browser/messenger apps)
    3. the package's middle part split on dots, or the exe stem title-cased
    4. a purged ID gives `unknown app (purged, ID n)`
  * `user_label(sid: str, names: dict[str,str]) -> str` → `"alice (S-1-…)"`, `"SYSTEM (S-1-5-18)"`, or the raw SID.
  * `build_activity(cam, wal_changes, reg, names, tz) -> list[dict]`. Keys: `when_utc, when_local, end_utc, end_local, duration_s, duration_text, app, app_id, app_kind, feature, feature_id, access, user, source, exe_path, sha1, ref, note`. Sorted by (`when_utc`, `app`). Sources:
    * `Database`
    * `Database (WAL – not yet in .db)`
    * `Recovered (deleted)`
    * `Recovered (WAL slack)`
    * `Registry (last use)`
    * `Database + Registry`
    * `Location prompt`
  * `app_summary(activity, perms) -> list[dict]`
  * `feature_view(activity) -> list[dict]`
  * `permission_view(consent, reg, activity, names) -> list[dict]` with `flag` ∈ {"", "Used while now Deny", "Never used"}
  * `program_view(cam, activity) -> list[dict]` with `location_flag` ∈ {"", "Temp folder", "Downloads", "Other drive"}
  * `day_counts(activity) -> list[{"day","feature","count"}]`

- [ ] **Step 1: Write the failing tests** using synthetic `cam`/`consent`/`reg` dicts:
  * `test_activity_sorted_and_sentence_fields`
  * `test_wal_row_labelled`
  * `test_db_and_registry_same_event_merged`
  * `test_purged_lookup_label`
  * `test_permission_mismatch_flag`
  * `test_views_without_consent_or_registry` (the permission view returns one row: `{"note": "no consent data"}`)
  * `test_feature_and_app_labels` (`microsoft.windowscommunicationsapps_8wekyb3d8bbwe` → "Mail and Calendar"; `C:\…\brave.exe` → "Brave")
  * `test_duration_text` (5.0 → "5.0 s"; 754 → "12 min 34 s"; 0 → "instant")
- [ ] **Step 2:** Run `-k views` → FAIL.
- [ ] **Step 3:** Implement `views.py`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: analyst views (activity, apps, features, permissions, programs)`.

### Task 4: Excel export

**Files:**
- Create: `winwitness/xlsx.py`
- Test: `tests/test_xlsx.py`

**Interfaces:**
- Produces: `write_xlsx(path: str, sheets: list[tuple[str, list[str], list[list]]]) -> None`. Each entry is (sheet name ≤ 31 chars, header, rows). Numbers are stored as numbers and everything else as inline strings. The header row is bold and frozen, and autofilter is on.

- [ ] **Step 1: Write the failing test** `test_xlsx_roundtrip`. It writes 2 sheets, including one cell with `<&>"` and one starting with `=`. It reopens the file with `zipfile` and `xml.etree`, then asserts:
  * the sheet names
  * cell text equals the input
  * `=cmd` is stored as a string (no formula element)
  * `[Content_Types].xml` lists both sheets
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Files written: `[Content_Types].xml`, `_rels/.rels`, `xl/workbook.xml`, `xl/_rels/workbook.xml.rels`, `xl/styles.xml` (one bold font) and `xl/worksheets/sheetN.xml`. Columns are A..ZZ.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: stdlib Excel export`.

### Task 5: Report v2 and output layout

**Files:**
- Modify: `winwitness/report.py` (add `write_html_v2(path, ctx)`; keep `write_html` for the technical appendix content builder)
- Modify: `winwitness/cli.py` (build views; write `WinWitness_report.html` v2, `WinWitness_activity.xlsx`, top-level analyst CSVs; move the old CSVs to `csv/technical/`)
- Modify: `tests/test_robustness.py` (update expected paths)
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: Task 3 views, Task 4 `write_xlsx`.
- Produces:
  * `write_html_v2(path: str, ctx: dict)` with ctx keys `summary, activity, apps, features, permissions, programs, recovered, findings, day_counts, technical_html, method_html, evidence, integrity_ok, tz_label, tool`.
  * Output files at top level of the output folder: `WinWitness_report.html`, `WinWitness_activity.xlsx`, `activity_timeline.csv`, `apps.csv`, `features.csv`, `permissions.csv`, `programs.csv`, `recovered.csv`, `findings.csv`, `winwitness_results.json`, `winwitness_results.sqlite`, `run_log.txt`, `MANIFEST.sha256`, `csv/technical/*`.

- [ ] **Step 1: Write the failing tests.**
  * `test_report_sections_in_order`: section ids `summary, activity, apps, features, permissions, programs, recovered, findings, technical` appear in this order.
  * `test_report_embedded_data_parses`: the `<script type="application/json" id="cam-data">` content is valid JSON, and its `activity` list is sorted by `when_utc`.
  * `test_report_large_activity`: 50,000 rows; the file is written; the JSON row count is 50,000.
  * `test_output_layout`: a CLI run on the fixture gives the top-level files above; `WinWitness_activity.xlsx` opens as a zip with 7 sheets.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement.** The HTML must:
  * show a sticky header with summary cards (system, users, period covered, uses, apps, recovered, integrity)
  * provide a filter bar (search, app, feature, user, source, from/to date) shared by the timeline, apps and features views
  * draw an SVG day chart, stacked by feature
  * group the timeline table by day; each row shows time, duration, app (plus kind), feature, access badge, user and source badge; clicking a row expands exe path, SHA-1 and record ref
  * render 500 rows per page
  * work in light and dark themes
  * collapse the technical details into `<details>`
- [ ] **Step 4:** Run the full suite → PASS.
- [ ] **Step 5:** Commit `feat: analyst-first HTML report v2 and output layout`.

### Task 6: Verification and docs

- [ ] **Step 1:** Run the CLI on the real evidence. The timeline must show:
  * Mail and Calendar contacts
  * Snipping Tool screen captures
  * Brave passkeys
  * 174 recovered rows
  * the WAL-slack row
  * 77 location prompts

  The app column must contain no package IDs.
- [ ] **Step 2:** Visual check in the browser at desktop and mobile width, light and dark.
- [ ] **Step 3:** README: update the Output and Run sections (hives are auto-detected; new files).
- [ ] **Step 4:** Full suite plus a 1,500-round fuzz → all pass.
- [ ] **Step 5:** Commit `docs: v2 report`. Ask the user before pushing.
