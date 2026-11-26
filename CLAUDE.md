# CLAUDE.md

`AGENTS.md` binds everything. Also read, in this order, before code work:

1. The noni direction layer (steering): `.noni-state/noni/direction/intent.md`,
   the head of `.noni-state/noni/direction/order.json`, and `.noni-state/noni/decisions/`
   (a SessionStart hook prints the brief; run `noni brief --repo .noni-state` if it did not).
   Precedence: newest live decision record > intent.md > stop and ask the owner.
   Ask-first items are never decided autonomously.
2. The approved spec in `docs/superpowers/specs/` and the active plan in
   `docs/superpowers/plans/` (the plan argues from the spec; read both).
3. Tickets are the tracker; work claims belong to the pi-rukas driver — do not
   create parallel claim files.
