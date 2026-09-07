# Current state

## Goal

Close the Phase 2 PostgreSQL/manual smoke gate before public disclosure, then continue to LN implementation.

## Confirmed

- The fixes belong in `/home/talvasconcelos/Work/lnbits_pg`.
- The intended manual test checkout is `/home/talvasconcelos/Work/lnbits-arkade`, a separate dirty checkout at `46da68cca`; it lacks the current frontend fixes. Preserve its unrelated changes and do not overwrite it blindly.
- The intended database is `arkade`. The `demo` database must never be used for tests.
- Frontend fixes completed: twelve word restore inputs with paste, legacy password unlock compatibility, six digit validation for new PINs, and safe migration-required UI handling.
- Safe old-account and PostgreSQL CAS changes are present. Relevant verification completed: 208 Arkade tests, 6 enrollment e2e tests, Ruff/Black checks, and generated bundle validation. The e2e runner previously inherited `.env` and therefore is not evidence of isolated database safety.
- Terra review found no remaining product code blocker in the reviewed scope.
- Demo audit found no detectable account, wallet, or payment mutations during the known 22:12–22:20 window and no Arkade rows; this cannot prove that no other effects occurred.

## Open gate

Manual smoke and disclosure are still blocked. User1’s actual state and the intended `arkade` instance have not been safely verified after transferring the fixes. Persistent smoke artifacts under `/tmp` are not authoritative evidence.

## Next checkpoint

Review and safely transfer the current fixes to the intended dirty checkout while preserving its changes. Make every runner require an explicit isolated `arkade` target and verify the target before tests. Then debug user1, run the explicit PostgreSQL/Arkade smoke (two accounts, receive, outgoing), and record evidence for the disclosure gate.

## Constraints

- Do not store or repeat supplied user passwords or secrets.
- Do not use the demo database for tests.
- Keep Luna delegation low-reasoning/project-scoped for coding or churn work; obtain Terra review before declaring completion.
- Do not edit `AGENTS.md`, generated vendor assets, or unrelated dirty changes.

## Stop condition

Stop before declaring Phase 2 closed unless the intended checkout, explicit `arkade` database, user1 behavior, and the complete manual smoke flow all pass with captured evidence.
