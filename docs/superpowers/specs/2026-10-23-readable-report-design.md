# WinWitness v2: an analyst-first report

## Intent
The v1 report is technically complete but unreadable. It opens on database internals, shows raw package IDs instead of app names, and never directly answers the analyst's question:
**"Which application used which feature (camera, microphone, location…), when, for how long, and was it allowed?"**
That answer, in time order, must be the first thing the report shows. Everything else supports it.

The user approved these requirements (2026-10-23):
1. **Activity timeline:** one row per use, in time order. Columns: start/stop (UTC and local), duration, app (friendly name plus exe path or package), feature, allowed/blocked, user.
2. **Per-app summary:** features used, number of uses, first seen, last seen, total duration.
3. **Per-feature view:** every app that used camera, microphone, location, and so on.
4. **Permission state:** Allow / Deny / Prompt per app and feature, set against actual use; mismatches flagged.
5. **Program identity** for desktop apps: exe path, SHA-1, first seen; odd locations flagged (Temp, Downloads, other drives).
6. **Completeness:** WAL rows, recovered deleted rows and registry ConsentStore last-use, each clearly labelled by source.
7. **Forensic soundness:** inputs never modified; hashed before and after; live vs recovered separated; never guess.
8. **Usability:** filters (app, feature, date range, user, source), a day-by-day activity chart, anomaly flags, exports.

## Calls made by Claude (stated to the user, not yet objected to)
* **Report section order:**
  1. Summary
  2. Activity timeline
  3. Apps
  4. Features
  5. Permissions
  6. Programs
  7. Recovered
  8. Findings
  9. Technical details (collapsed)
* Single self-contained offline HTML file. Data is embedded as JSON and rendered and filtered by inline JS.
* Excel export (`WinWitness_activity.xlsx`, one sheet per view), written with the standard library only. The analyst-facing CSVs sit at top level and the technical CSVs move to `csv/technical/`.
* Friendly names come from: AppNames → known-app table → a cleaned-up package/exe name. The raw ID is always kept in its own column.
* Offline registry hive reader:
  * `NTUSER.DAT` gives ConsentStore last-use and per-app permission.
  * `SOFTWARE` gives HKLM consent, retention settings, OS version and ProfileList (SID → account name).
  * Hives are found automatically in the evidence folder.
* SIDs are shown as `account (SID)` when the name is known; well-known SIDs are named (S-1-5-18 = SYSTEM).

## Goals / non-goals / anti-goals
* **Goal:** an analyst can answer "what used the mic on the 14th" in under 10 seconds from the first screen.
* **Non-goal:** live acquisition, transaction-log (.LOG1/.LOG2) replay for hives.
* **Anti-goals:**
  * any number in the report that isn't traceable to a source record
  * guessed app or capability names for purged lookup IDs (show "unknown app (purged, ID n)")
  * the report hiding recovered or WAL data behind internals

## Constraints
Python 3.10+ standard library only; inputs read-only; existing engine behaviour and all 38 public tests unchanged; deterministic output.
