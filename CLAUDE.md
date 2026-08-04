# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

agentbox runs an agentic coding tool inside an isolated, per-project environment: it resolves the project root, merges layered config, selects a backend meeting the project's isolation floor, builds a toolchain image, constructs a masked view of the workspace that hides secrets, starts a default-deny egress proxy, and execs the agent. Read `README.md`, `docs/security.md`, and `docs/configuration.md` for the user-facing contract.

## Build, test, lint

```console
go build -trimpath ./cmd/agentbox   # single static binary, one dep (BurntSushi/toml)
go test ./...
make all                            # fmt-check + vet + build + test (the pre-PR gate)
go test ./internal/config/          # one package
go test -run TestName ./internal/config/   # one test
```

- Toolchain is pinned by `go.mod` (Go 1.26). `gofmt` clean and `go vet` clean are enforced in CI; run `make fmt-check vet` before finishing.
- Some suites are **deliberately excluded** from `go test ./...` and run as dedicated CI jobs that **fail if they skip instead of run** (a green build that silently omitted them is the failure mode those jobs prevent):
  - `make test-privileged` — the Layer-0 real-mount test (`TestLayer0RealMounts`), needs root/`CAP_SYS_ADMIN`.
  - `test/vmconformance/` — needs KVM + a kata/krun runtime; gated behind `AGENTBOX_VM_CONFORMANCE=1` and `AGENTBOX_BIN`.
  - Container/VM end-to-end tests need a live Docker daemon; the policy/plan/state logic they'd exercise is covered at the unit level instead.
- The ignore-matcher conformance suite differentially tests against `git check-ignore`, so `git` must be on `PATH`.
- `make man-lint` (needs mandoc/groff) and `make completions` regenerate the man-page lint and shell completions.

## Architecture

Everything flows through a single build-a-plan-then-enact pipeline. **Building a plan never creates or starts anything** — `--dry-run` and all inspection commands (`config`, `mounts`, `masks`, `backends`) produce the same `Plan` the enacting commands do.

**Entry & dispatch** (`cmd/agentbox/main.go`): hand-rolled flag parser, then *interpretation* — the first non-flag arg that is in the closed `reserved` subcommand set dispatches to a `Cmd*` method; anything else (or after `--`) is a command to run *inside the box*. Adding a reserved subcommand is a breaking CLI change. `proxyd` is a hidden entry point (the vm-backend host proxy daemon), intercepted before parsing. agentbox owns its own exit codes per `sysexits.h`: **64** usage, **69** isolation floor unsatisfiable, **77** untrusted config, **78** invalid config; the in-box command's exit code is otherwise passed through verbatim.

**`internal/app`** wires subsystems into commands. `Resolve()` (`app.go`) is the front door for every command: workspace detection → config load → flag overlay → workspace-trust check, producing a `Ctx`. `plan.go` turns a `Ctx` into a `Plan` (box identity, backend availability, image resolution, mask set, network policy, guest workdir). `commands.go`/`lifecycle.go`/`inspect.go`/`scaffold.go`/`trust.go` are the `Cmd*` methods.

**`internal/config`** — 7 layers merged lowest-to-highest: built-in → system → user → workspace → profile → environment → flags (`load.go`). `--origin` attributes every key to the layer that set it. Static validation is total: unknown keys and backend-scoped keys placed in the wrong section (`[security.container]` vs `[security.vm]`) are **hard errors on every machine**, not just where they'd apply. `extends` chains and profiles resolve here.

**`internal/backend`** — defines the isolation *contract* both backends implement (`backend.go`, `BoxSpec`), plus the selection algorithm, expressed with no Compose YAML or hypervisor config leaking in. Two tiers: `container` (Docker / rootless Podman, `container.go`) and `vm` (Kata via docker / libkrun via podman, `vm.go`). Tiers are **not equivalent and never silently downgraded**: a project declares `min_isolation`; if nothing meets it, exit 69 naming what's missing. Lowering the floor requires `--force-isolation`, which is recorded in box metadata and warned on every invocation.

**`internal/mask`** — secret hiding, enforced host-side. `ignore.go`'s matcher (differentially tested against `git check-ignore`) and the mask-set computation are **shared, single-implementation code**: do not fork or duplicate them — a second implementation doubles the surface for a silent failure to mask a secret. `layer0.go` is the per-box mount plan. Modes: `view` and `filter` (Layer-3, vm tier only, served by `internal/share` — agentbox's own FUSE share daemon, spawned as the hidden `fsd` subcommand). `auto` under the vm tier resolves to `filter` where the seam is deliverable (root + `/dev/fuse`), else to `view` **with a warning**; an explicit `filter` that cannot be delivered is a config error naming why. The filter daemon compiles patterns from contents frozen at spawn — never re-read from the guest-writable tree.

**`internal/netpol`** — default-deny egress. `netpol.go` compiles bundles + allowlist into a `Policy` and generates squid config; `proxyd.go` is the vm-tier host proxy daemon (per-box listeners) run via the hidden `proxyd` subcommand. Widening a **bundle** widens every user's egress and must be justified in `CHANGELOG.md`.

**`internal/state`** — XDG layout under `$XDG_STATE_HOME/agentbox` (`state.go`), atomic project/box metadata, two-level locking (`lock.go`). `BoxMeta` freezes config/image/mask digests at creation and recomputes+compares them on every later invocation to detect drift.

**Supporting packages**: `internal/identity` (workspace detection, two-level project/box identity, ordinal aliases like `-n 2`), `internal/tree` (`shared`/`worktree`/`copy`/`auto` tree modes; extra boxes get their own git worktree + branch), `internal/image` (feature-digest-keyed generated Dockerfile), `internal/workspace` (root detection).

## Invariants (the review bar is stricter than usual here)

- **No silent weakening.** Anything reducing an enforced property — masking, egress policy, isolation floor, inter-box separation — must be *loud*: an error, or a warning on every invocation. This is the criterion applied most strictly in review; tests for masking/egress/trust must cover the *refusal* path, not just the happy path.
- **Documented behavior is the contract.** A behavior change must update the README, the relevant `docs/*.md`, and the man pages under `docs/man/`. Intentional divergences go in the README "deviations" list — silence about them is not acceptable.
- **Committed workspace config is untrusted by default.** `[hooks]` and `[[workspace.mounts]]` from the workspace layer are refused (exit 77) until `agentbox trust` (TOFU; any edit invalidates trust). The `trustLenient` read-only commands in `main.go` proceed with a warning so an untrusted config can still be reviewed.
- Diagnostics go to **stderr**; **stdout belongs to the in-box command**.
