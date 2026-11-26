# AGENTS.md — permanent rules (static-file rule: no dates, versions, or progress here)

Mutable facts (design, build order, steering) live in: `docs/superpowers/specs/`,
`docs/superpowers/plans/`, and the noni direction layer (`.noni-state/`, briefed at
session start). Read those before touching code.

## Pre-push gate list (run all, every push)

1. `scripts/run_tests.sh` — exit 0 (discovers `tests/test_*.sh`, configures/builds, runs `ctest`).
2. `scripts/hygiene_grep.sh` — exit 0 (privacy patterns + tracked-file assertions).
3. `clang-format --dry-run --Werror` clean on every changed C/C++/ObjC++ file.
4. `scripts/check_patches.sh` — exit 0 whenever `patches/` or `docs/superpowers/plans/` changed.
5. Offline doctrine check: `grep -rniE 'SecItem(Add|CopyMatching|Update|Delete)' --include='*.cpp' --include='*.h' . | grep -v testing` must return empty (SecItem calls live only in `.mm` backends).

## Hard budgets (ratchet-only)

- Any source file < 800 lines; any script < 200 lines; the plan/spec docs are exempt.
- Tests never touch a real keychain, network, or live account endpoint — only `FakeKeychainBackend`.
- Only the env vars named in README may be read via `getenv`.

## Banned constructs

- `SecItem*` outside `*.mm` Apple backends; security prompts bypassed or auto-accepted in tests/CI.
- Secrets (master key, credentials, CSV contents) written to logs, telemetry, crash fields, or persisted raw buffers.
- SQL built by string concatenation — bound parameters only.
- Hand-rolled crypto; OpenSSL EVP only.
- Origin matching weaker than exact scheme+host-casefolded+port-default-stripped; never store/return http except `localhost` with explicit port.
- Cross-origin save: a record is keyed to `frame_origin` and saving requires `submit_action_origin == frame_origin`.
- Admin surfaces (`list/export_csv/import_csv/delete_bulk`) reachable without a live `CapabilityToken` — fail closed when re-auth unavailable.

## Privacy

- Nothing personal in any tracked file (names, hostnames, paths outside the repo). The
  hygiene grep builds its patterns with the split-word idiom and must itself print no
  matched substring; a pattern that matches the repo's own tooling is a bug in the
  pattern, not the repo.
- `.noni-state/`, `.superpowers/sdd/`, `.hygiene-denylist` are excluded via
  `.git/info/exclude` — never a committed `.gitignore` entry for private paths.
- Ticket bodies describe external systems as "a live gateway"; cite commits, not URLs
  carrying private org names.

## Git policy

- Conventional Commits (`feat|fix|test|docs|ci|refactor:`), plus the attribution lines the
  session prescribes. `Fixes #N` goes in the PR body only, never in commit messages.
- Branches: `feature/<slug>`; never push `main` (bootstrap commit excepted); never
  rebase a pushed branch; never force-push; merge origin/main INTO branches.
- Merge grant: **none** — agents open PRs and park; the owner merges (squash-merge only).
  The pi-rukas work driver must be left without a merge grant.
- One PR per ticket; keep diffs inside the ticket's scope.

## Owner-reserved files

`README.md`, `AGENTS.md`, `CLAUDE.md`, `LICENSE`, `scripts/hygiene_grep.sh`,
`scripts/run_tests.sh`, `.github/workflows/*`, `docs/superpowers/specs/*` — edits need
an explicit owner ruling recorded via `noni decide` before the PR.

## Verification discipline

Any claim of "done/works/green" must quote same-message tool output (ctest summary,
hygiene exit code, `gh` output). `skipped`/`neutral` CI checks are not passes. Never
report a PR, issue, or run that has no tool output proving it in the same message.
