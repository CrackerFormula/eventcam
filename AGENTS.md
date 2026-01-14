# Agent Notes

## Purpose
Track session notes, decisions, and outstanding tasks.

## Session Notes
- 2026-01-13: Added camera resolution fallback chain with device capability max and UI display of actual resolution.
- 2026-01-13: Added selfie mode toggle to switch between rear/front camera and mirror preview.
- 2026-01-13: Added event dashboard "Top devices" stats with per-device upload counts (DB-backed; local fallback).
- 2026-01-13: Attempted to run `npm install` but `npm` not available in environment.
- 2026-01-13: Note: app uses Docker for deployment/runs.

## Open Questions
- Decide top devices list size and format.
- Decide if camera resolution should move out of the status line.

## Next Steps
- Install Node/npm (or confirm runtime) if rebuild/run is still desired.

## Decisions
- Top devices list: keep 3 entries to stay concise on the dashboard.
- Camera resolution: keep it in the status line to avoid adding UI clutter.
