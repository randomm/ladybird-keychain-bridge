# Contributing

Work is ticket-driven and agent-run; the rules live in `AGENTS.md` (binding) and the
spec/plan docs. In short:

1. Pick the next issue from the order list (steering layer) — do not self-assign.
2. Branch `feature/<slug>` off `main`. Tests first: write the failing test, read the
   failure, then implement (RED-GREEN).
3. Every push passes the full gate (`scripts/run_tests.sh`, hygiene grep, clang-format).
4. One PR per ticket; Conventional Commits; `Fixes #N` in the PR body only.
5. Agents never merge — the owner squash-merges.
