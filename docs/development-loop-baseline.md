# U01 development-loop baseline evidence — 2026-10-21

**Attempt #172 disposition: unqualified.** The artifact-backed `prepare` phase completed, but
the required `verify` phase was not dispatched. The prepared positive and stale
PRs are ready for review (`draft: false`), while the current integration-testing
instructions require owner review and commands while both PRs are drafts. The
run's protected-main source creates ready PRs and prints the review/command
instructions without a draft transition. No manual state change was made to
bridge that discrepancy. This is a prepare-versus-draft-contract mismatch, not a
production blocker or a successful baseline.

## Prepare evidence

- Authenticated actor: `civitaspo` (GitHub user ID `4525500`). Protected `main`
  was the signed source `6287b76f24d5f7023e84cd932bc84437c417447e` at dispatch.
- Prepare run: [#172 / `39543607598`](https://github.com/civitaspo/securefix-server/actions/runs/39543607598),
  attempt 1, `workflow_dispatch`, source/workflow SHA
  `6287b76f24d5f7023e84cd932bc84437c417447e`, completed successfully from
  `2026-10-21T04:21:44Z` to `2026-10-21T04:22:58Z` (74 seconds).
- The run's `scratch` job completed successfully from `04:21:57Z` to `04:22:57Z`.
  Build and baseline jobs passed. Bootstrap, bootstrap-scratch, provider-release,
  and legacy-bootstrap jobs were skipped; no publish, activation, distribution,
  or provider phase was requested.
- Immutable artifacts from that exact run:

  | Artifact | ID | GitHub digest |
  | --- | ---: | --- |
  | `candidate-runtime` | `12319879865` | `sha256:fee6afaa5f82cb9708abb4ad1f713536535def4c672661eec34d2d4b9605de77` |
  | `scratch-fixtures` | `12320701036` | `sha256:585995eaecfc951e1e5085e63bc4d5a8468f2ed3ba05cdf27b2a7468b860c2f0` |
  | `control-probe` | `12320765960` | `sha256:a889d54b4cd8d3ed577ee3f13db98698dee640cb3eea47c3817a6d6fbe6ac291` |

  The downloaded `state.json` SHA-256 is
  `808439c70cccedd8cea0569d52774273315c3b012f7d53e11f8dccff6719e354`.
  Extracted candidate executable SHA-256 is
  `5afbef63a06ded7e6f2f6d166777f331d151b505aa1af9525727fa568c7a525c`;
  its bundled policy SHA-256 is
  `91292daf7e6229ec64d66618926b10c4785e67bb3b1cd31d1a9bc1646464cc1c`.
  The control-probe output records `.generation_one` as
  `69dfaf3a47211d6d1697848f1b3a23be1a22e90fa3f7cb1942ffda89c5d9412e` and
  reports its three descriptor/CAS/replay checks as true. That probe is separate
  from the later positive/stale approval review requirement.

## Exact scratch state and current-lane observations

`state.json` binds the run to repository `civitaspo/testing-securefix-server`
(ID `1410312556`), base `d0accd7c2ce9d3e02375a25f5da52f72461328c5`, and the
published baseline runtime source `1b35591e74eeae8fe848d16c6fcae0ba8fb75f6c`.
The live scratch `main` still resolved to that base at readback. The three
run-created PRs remain open at their recorded heads:

| Fixture | PR | Exact head | Branch | Readback |
| --- | --- | --- | --- | --- |
| Positive | [#359](https://github.com/civitaspo/testing-securefix-server/pull/359) | `93d8678cddd45a58afaa8410459babe65831bdf8` | `securefix-integration-positive-1792556527114210394` | App-authored, ready (`draft: false`), base unchanged |
| Stale head | [#360](https://github.com/civitaspo/testing-securefix-server/pull/360) | `01fe1c40db813f48fa5d141fe8bd990e9bd2f1af` | `securefix-integration-stale-1792556527114210394` | App-authored, ready (`draft: false`), base unchanged |
| Distribution | [#361](https://github.com/civitaspo/testing-securefix-server/pull/361) | `03c9ac17d49852ad24fb7baf22a3f5d06b258e3d` | `securefix-integration-distribution-1792556527114210394` | App-authored, open on the same base |

GitHub reported the fixture commits as verified, and the relevant CI/fixture
checks on the prepared heads completed. The expected client/server request path
also ran for the positive and stale fixtures:

- Scratch [testing-Approve Request #531 / `39543652164`](https://github.com/civitaspo/testing-securefix-server/actions/runs/39543652164)
  completed successfully for #359. Its `approve / capture` job dispatched the
  request to the server. Server [testing-Approve Pull Request #774 /
  `39543719252`](https://github.com/civitaspo/securefix-server/actions/runs/39543719252)
  completed validation and apply successfully.
- Scratch [testing-Approve Request #532 / `39543669026`](https://github.com/civitaspo/testing-securefix-server/actions/runs/39543669026)
  completed successfully for #360. Server [testing-Approve Pull Request #775 /
  `39543732219`](https://github.com/civitaspo/securefix-server/actions/runs/39543732219)
  completed validation and apply successfully.
- Both server runs produced a `civitaspo-bot` approval on the exact fixture
  head. Review IDs are `5594940908` on #359 at `04:23:49Z` and `5594943779` on
  #360 at `04:24:19Z`. Each body carries control marker
  `824f3066c5d35178102dad38ccd00f375d5cdcd6e31343b445b653c493fb853c`. This
  matches the canonical identity of the live scratch descriptor at base
  `d0accd7…` (generation 10, source
  `865a26535fb9a1756bf255df9ecbc58199c66c3f`). These are expected test-lane Bot
  reviews, not owner reviews and not a substitute for the owner review required
  by the direct scratch harness, which uses the control-probe `.generation_one`
  marker above.
- The distribution fixture's approval request was rejected during server
  validation because the current-head owner authorization was missing; the
  corresponding negative policy feedback is part of prepare. It is not counted
  as a passing verify scenario.

Before any owner action, an independent readback confirmed #359 and #360 still
had the exact prepared heads/base, only the known Bot reviews, and no issue or
review comments. A guarded owner-review command was attempted at `04:25Z` with an
incorrect precondition requiring zero total reviews. It stopped before invoking
`gh pr review` because the expected Bot review already existed. No owner review,
`/approve`, `/merge`, ready/draft transition, review dismissal, or verify
dispatch was made; the Bot reviews were preserved. `gh auth status` showed the
owner's keyring identity, with no `GH_TOKEN`, `GITHUB_TOKEN`, or Bot-token
environment override in that shell.

## Verification boundary

The source `6287b76` prepare code creates the positive PR without a `draft` field
and creates the stale PR through the generic ready-PR helper. Its emitted
instructions request the exact-head owner review and separate commands, but the
current `docs/integration-testing.md` procedure requires those actions while the
positive and stale PRs are drafts, followed by ready-event checks. Because the
prepared PRs are already ready, the prescribed draft rejection and ready-event
sequence could not be followed from this state. No state was changed manually
and the verify phase was not dispatched.

At this attempt's readback, all three run-owned fixture PRs remained open. The
historically unowned PRs #299 and #300 were not touched. Raw run/artifact
snapshots and readbacks are in `/private/tmp/securefix-refactor-c80e/baseline/`.
Developer edit latency and token usage were not measured. This evidence
establishes a successful prepare and the observed current-lane
requests/reviews; it does not qualify the pre-refactor end-to-end scratch
baseline.

## Follow-up candidate probe: draft lifecycle only

**Result: verified in the scratch repository; not a full development-loop
baseline.** The separately reviewed candidate contains only the native draft
lifecycle fix in `src/integration.rs` and the required prerelease version bump
in `Cargo.toml`/`Cargo.lock`. Candidate `5b3c9e4044a33934db8b7ed2dc4c2e6c202d2343`
is a signed child of protected-main base
`6287b76f24d5f7023e84cd932bc84437c417447e`; GitHub verified the commit. CI
run [#39547491916](https://github.com/civitaspo/securefix-server/actions/runs/39547491916)
completed successfully, including formatting, tests, Clippy, executable
verification, and actionlint. Its PR-base version-comparison step was skipped
because the run used `workflow_dispatch`; that check is not claimed here.

The artifact-backed scratch prepare run
[#39547730823](https://github.com/civitaspo/securefix-server/actions/runs/39547730823)
and verify run
[#39549852692](https://github.com/civitaspo/securefix-server/actions/runs/39549852692)
both completed successfully on the protected-main workflow source
`6287b76f24d5f7023e84cd932bc84437c417447e`. Verify reused the exact candidate
CLI artifact from prepare (ID `12322181647`, digest
`sha256:275f692a94a725a5c96772f9d8a6bd54c58bf53e9e52e77d4e7da0e32924ad09`);
it did not build a different candidate. Prepare's scratch-fixtures artifact
(ID `12322671386`, digest
`sha256:2c08d2f013b6668b61bd0f9f0328537be2a7ce26f31941b3fb6d5945340074fc`)
and control-probe artifact (ID `12322022095`, digest
`sha256:ce4ecb033cb286a81e50ec8b2df659588f8a8dbe5dc24e416628493a63bbd4b3`)
were consumed by verify. Verify uploaded these immutable results:

| Artifact | ID | GitHub digest |
| --- | ---: | --- |
| `candidate-runtime` | `12322184279` | `sha256:1cf23c3e1d1026c15346c6a5fbdbc1c8a9488876c1a8d0f1995a1b61239d8ac1` |
| `scratch-fixtures` | `12322149669` | `sha256:c5ffd8f18091f856c02a79371649996d28201820cda959eaa554d400a0aed62a` |
| `control-probe` | `12322549316` | `sha256:86abde2fd3c03ed2710d36c8afabd57a9c7bf991db04447c6328a942774cef88` |

The downloaded verify `state.json` SHA-256 is
`4241575597c052c0089bffaca29f0df53447dd983c3c0fd127fd55b93c3abacd`; its
`verification.json` SHA-256 is
`d9a06ad6866ec9a34580eb017ffb1cc8dbf49cbe1f9747da80bc94e606a98b94`. The
positive fixture #362 merged at `4a3c07e5e00ae9860d186afb337a2b50a96fe2c4`.
The stale fixture #363 was closed unmerged after its head changed to
`b45a9717fad8069a421060b70bdbe7186ca61a8c`; the distribution fixture #364
was closed unmerged. The verify control probe reported source advance kept the
descriptor, expected-head conflict rejection, and stale-identity rejection
after ABA all `true`. Its three descriptor generations were
`4f87cb3d01cd847faef16072167c964e0926b1f5354f3c83ea9770c6f46677c9`,
`ebfc2e1aa86fcd2c5b5bd444695e4c3312cc6558fa225bca708337616a18f3e3`, and
`c17451c8113904db9e4889f0d33ca896fbd0b78ad3561ea974a3740fa55ef6f0`. The
probe explicitly reports production publication, activation, and distribution
as `false`.

The follow-up sequence exercised the draft guard in scratch caller run
[#39548758690](https://github.com/civitaspo/testing-securefix-server/actions/runs/39548758690).
After the ready transition, the scratch approval caller
[#39549407901](https://github.com/civitaspo/testing-securefix-server/actions/runs/39549407901)
and server handler
[#39549485264](https://github.com/civitaspo/securefix-server/actions/runs/39549485264)
completed successfully; the corresponding policy-check caller and server
handler (#39549407843 and #39549482406) also completed successfully. The verify
run then exercised stale-head handling, same-head review/policy-check replay
rejection across a control generation, scratch merge, and generated caller
distribution checks. Verify cleanup removed its fixture branches; independent
readback found #362 merged, #363/#364 closed unmerged, no labels, and the server
main unchanged at
`6287b76f24d5f7023e84cd932bc84437c417447e`. The successful candidate only
qualifies this legacy native scratch flow and its draft lifecycle. It does not
include or validate the proposed development-loop architecture or workflows;
edit latency, token use, and a full pre-refactor baseline remain unmeasured.

## Cleanup of the first attempt's fixtures

After recording the follow-up evidence, a fresh fenced cleanup closed #359,
#360, and #361 unmerged and deleted only their exact run-owned branches. Their
heads and file sets matched the recorded fixtures; no owner commands or reviews
had been added, and no queued or in-progress integration-fixture writers were
present. The expected scratch-main advance from the old base
`d0accd7c2ce9d3e02375a25f5da52f72461328c5` to #362's merge commit
`4a3c07e5e00ae9860d186afb337a2b50a96fe2c4` was one commit. Server main stayed
at `6287b76f24d5f7023e84cd932bc84437c417447e`; candidate branch
`integration/native-draft-lifecycle-c80e` stayed at
`5b3c9e4044a33934db8b7ed2dc4c2e6c202d2343`. This disposal does not qualify the
failed #172 attempt. PRs #299 and #300 were not touched.
