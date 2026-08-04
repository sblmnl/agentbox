# Changelog

All notable changes to agentbox are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) with the caveat that the configuration schema
is only frozen at 1.0. The full policy — what the version number promises,
and how each release is interrogated for breaking changes — is in
[docs/versioning.md](docs/versioning.md).

Network **bundle** changes are always listed explicitly: widening a bundle
widens every user's egress policy.

## [Unreleased]

`0.0.1-dev` — the initial version, still in development. **Nothing has been
published yet:** there is no prior release, no tags, and no packages, so
everything below is new rather than a change relative to some earlier
version. This section becomes `0.0.1` at the first tagged release.

### Fixed

- **Bundle `agent:claude-code` gains `platform.claude.com`.** Claude Code
  contacts `platform.claude.com` to authenticate before it makes its first
  API call, so a box built on the stock bundle failed at startup with
  "Failed to connect to platform.claude.com: ERR_SOCKET_CLOSED" while
  `api.anthropic.com` tunneled normally — the proxy was denying the auth
  host. This widens the bundle by one host, in the same trust domain as the
  four already in it, and is required for the agent to start at all.
- **Removing the default box no longer dead-ends the project.** `agentbox rm`
  left `default_box` naming the box it had just deleted, so every later
  invocation resolved the default, found nothing, and refused to run until
  the user set a new one by hand. `rm` now adopts the sole surviving box as
  the default (one candidate is not a guess) or clears it when several
  remain, saying which. Resolution also tolerates a default written by an
  older agentbox: with exactly one box it is used and said out loud, and with
  several it still refuses rather than attaching the agent to the wrong box.
- **`prune --idle` now reaches boxes outside the current project.** It
  derived each candidate's engine resource name by building a plan, and a
  plan names resources after the project it was built in — so stopping an
  idle box in any other project targeted a name that did not exist and was
  reported as "could not reclaim". The name now comes from the same
  cross-project scan that decides what is claimed.

### Added

- **The Layer-3 filtered share runs unprivileged.** `mask_mode = "filter"`
  previously required agentbox to run as root, because the share daemon
  mounted `/dev/fuse` with `mount(2)`. It now mounts through the setuid
  `fusermount3` helper when not root, receiving the device descriptor over
  `SCM_RIGHTS`, and retracts the mount through the helper too — so the whole
  daemon runs in the invoking user's context. The root path is unchanged and
  still taken first. This **strengthens** the rootless default: under the vm
  tier, `mask_mode = "auto"` on a non-root agentbox now resolves to `filter`
  rather than degrading to `view`, so a mid-session `.env` is masked where
  it previously was not. The unprivileged route needs `user_allow_other` in
  `/etc/fuse.conf` (a one-time root edit) because the runtime's virtiofs
  server may run under a different uid than the mount owner; agentbox
  requires it on that route unconditionally and names it in the refusal
  rather than mounting a share the guest cannot traverse.
- **CLI contract.** Reserved-subcommand dispatch, `--` forcing an in-box
  command, stdout/stderr separation, `sysexits.h` codes (64 usage, 69
  isolation floor, 77 untrusted config, 78 invalid config; the in-box exit
  code otherwise passed through verbatim), signal forwarding, and a TTY only
  when stdin+stdout are terminals.
- **Identity.** Workspace detection stopping at `$HOME`/filesystem
  boundaries; a project key plus per-box identity; ordinal aliases (`-n 2`);
  default-box resolution that errors rather than guesses.
- **Tree modes.** `shared` / `worktree` / `copy` / `auto`; extra boxes get
  their own `git worktree` on an `agentbox/<instance>` branch kept under the
  state dir so `git status` stays clean; `rm` preserves the branch unless
  `--delete-branch`.
- **Configuration.** Seven layers (built-in → system → user → workspace →
  profile → env → flags) with `--origin` attribution; array append with the
  `!reset` / `!value` escapes; `extends` with cycle detection; profiles; the
  `AGENTBOX_*` env layer. Unknown keys are hard errors, and backend-scoped
  keys placed in the wrong section are schema errors on every machine.
  Isolation floor is honored without downgrade; lowering it requires
  `--force-isolation`, which is recorded and warned on every invocation.
- **Image.** Backend-independent feature digest; generated Dockerfile with
  uid reclaim, filesystem-wide setuid strip, pinned + fingerprint-verified
  repo signing keys, telemetry/auto-updater disables, and no credentials in
  any layer. Three ways to choose the image in strict precedence:
  `[image].ref` (a prebuilt OCI image, used verbatim), `[image].dockerfile`
  (a Dockerfile you own, built as-is, content-addressed so edits rebuild;
  relative paths resolve against the config that set them, so one in
  `$XDG_CONFIG_HOME/agentbox` is a global baseline), else the generated
  Dockerfile from `[image].base` + `[toolchains]` + `[image].packages` +
  `[agents]`. Taking ownership via `ref`/`dockerfile` ignores declared
  toolchains and says so; `ref` wins when both are set.
  `AGENTBOX_UID`/`AGENTBOX_GID`/`AGENTBOX_GUEST_ROOT` are passed as build
  args. The default base is `ubuntu:26.04`.
- **Masking.** A single gitignore-semantics matcher, differentially tested
  against `git check-ignore`; per-box mask sets with rule attribution; the
  Layer-0 mount plan with an in-namespace applier; `mask_mode` with
  `filter`-under-container rejected as an error, not a downgrade.
- **Layer-3 filtered share.** `mask_mode = "filter"` under
  the `vm` tier: the workspace is served by agentbox's own share daemon
  (`internal/share`, a dependency-free FUSE passthrough run as the hidden
  `fsd` subcommand), interposed beneath the runtime's virtiofsd. Masked
  paths answer `ENOENT` and are omitted from directory listings; the
  filter is evaluated at every lookup from the same compiled pattern set
  as Layer 0, so a matching file created mid-session is masked and masked
  directories impose no tmpfs size cap; creating, linking, or renaming
  onto a masked name fails `EPERM`; renaming a directory that hides a masked
  entry fails `EBUSY`, so an anchored pattern cannot be dodged by moving an
  ancestor out from under it (view mode blocks the same move via the masked
  mountpoint); and pattern contents are frozen host-side at box start so
  in-guest edits to `.agentignore` cannot unmask. `auto` under `vm` now resolves to `filter` where the seam is
  deliverable (root + `/dev/fuse`) and falls back to `view` with a warning
  otherwise; an explicit `filter` that cannot be delivered is an error.
  Under filter mode, mask-drift detection hashes the pattern sources
  rather than the computed entry list, `masks --verify` asserts absence
  rather than emptiness, and `doctor` reports which way `auto` resolves.
  Covered by protocol-level tests (no mount needed), a privileged
  real-mount test that CI fails on skip, and vm-conformance guarantees.
- **Network policy.** `none` / `proxy` / `open`; the twelve 1.0-required
  bundles with telemetry endpoints split into separate `*:telemetry`
  bundles; deny-first evaluation; generated squid config with a terminal
  deny, audit lines, and long stream timeouts; proxy env in both casings.
- **State.** XDG layout under `$XDG_STATE_HOME/agentbox`; atomic JSON
  metadata; two-level flock locking with timeout diagnostics naming the
  holder. `BoxMeta` freezes config/image/mask digests at creation and
  compares on every later invocation to detect drift.
- **Container backend.** Docker / rootless Podman; an internal no-gateway
  network; a proxy sidecar; workspace-writability verification.
- **VM backend.** The `vm` tier on OCI-consuming VM runtimes — Kata
  Containers via docker (`kata`, `kata-qemu`, `kata-clh`) or libkrun via
  podman (`krun`) — driven through the same container-engine CLI and
  consuming the same OCI images as the container tier. Per-box backend
  selection; a host proxy daemon (the hidden `proxyd` subcommand) reached
  from the box over **vsock**; a host-side mask view. `security.vm` keys
  (`hypervisor`, `runtime`, `guest_root`, `nested_docker`, `memory_backing`)
  are scoped to this tier.

  Egress under this tier travels over vsock rather than the box's bridge.
  `HTTPS_PROXY` points at loopback inside the box, where a forwarder (the
  hidden `vsockfwd` subcommand, the same binary bind-mounted in) carries
  connections to the host daemon; the box network stays `--internal` and
  carries no egress. The bridge path it replaces was ordinary IP traffic to
  a host process, so a default-deny `INPUT` policy or a VPN kill-switch
  accepting only RFC 1918 as "local network" would drop it — invisibly to
  the container engine, and indistinguishable from a hung agent. vsock has
  no address to filter and is not visible to netfilter. Boxes are told apart
  by a per-box token minted at create time; a connection whose token matches
  no running box is closed unserved, and the audit log records the
  unforgeable peer context id (`cid<n>`) where a bridge listener recorded a
  client IP. Because the same binary runs inside the guest, `make build` now
  links it statically (`CGO_ENABLED=0`).

  If the guest cannot reach its proxy, the box now fails at start naming the
  likely cause instead of coming up healthy with every network call hanging.
- **Pruning.** `agentbox prune` reports what agentbox has left behind and can
  reclaim — state for vanished workspaces, engine containers, networks and
  volumes no box in agentbox state claims, mask views with no box to serve,
  and (with `--images`) built images no box references, with the engine's
  own size for each. It **reports and removes nothing by default**; `--apply`
  reclaims. `--idle` includes boxes past their idle timeout, which are
  stopped rather than removed, and `--json` emits the candidate set as data.
  Only resources agentbox itself would have created under that name are ever
  candidates, and a resource is matched back to its box by exact name before
  its derived suffixes (`-int`, `-egress`, `-home`, `-proxy`), so a box whose
  instance name ends in one of those is not mistaken for another box's.
- **Unified view: `agentbox ls --artifacts` and `agentbox status
  --artifacts`.** Answering "what is this box actually holding?" used to mean
  cross-referencing `status` against `docker volume ls` by hand: `ls` spanned
  projects but made no engine calls, `status` had live state but no
  artifacts, and `prune` reported only what *nothing* claimed. Both flags now
  list a box's container, networks, home volume and image, its host-side mask
  view and proxy listener under the vm tier, its working tree and branch, and
  its state directory — each resolved against what is actually there. An
  artifact the box expects and the engine does not hold reads `MISSING`; one
  its name claims but that it was not created with reads `unexpected`, which
  is how a sidecar orphaned by a switch to `network.mode = "none"` becomes
  visible at all. Expectations come from what the box was created with
  (its frozen `spec.json`), not current configuration, so ordinary drift —
  which `status` already reports on its own line — is not an alarm. `present`
  and `running` stay distinct answers: a stopped proxy sidecar beside a
  running box is a broken egress path, not a healthy one.

  `ls --artifacts` closes with every agentbox artifact on the host that no
  box claims, computed across all projects. It is the same name-to-box join
  `prune` runs, read in the other direction, over one shared implementation:
  nothing can appear both under a box and as unclaimed.

  Plain `ls` is unchanged and still makes no engine calls, so it answers with
  the container daemon stopped.
- **Bulk teardown: `agentbox prune --boxes`, `--running`, `--state`.** A live
  box was never a prune candidate at any flag combination, `--all` means
  "this project", and `rm` has no `--all`, so tearing down a machine was a
  shell loop. `--boxes` makes every *stopped* box in agentbox state a
  candidate across all projects, removing its guest, networks and working
  tree; `--running` also takes running boxes; `--state` also takes each box's
  persistent home. The escalation is deliberate and each step is named
  separately: `--running` or `--state` without `--boxes` is a usage error
  (exit 64) rather than a silent no-op, and a box whose backend is
  unavailable on this host cannot be inspected and is left alone as though it
  were running. Boxes prune declined to touch are named at the end of every
  run, so a partial teardown never reads as a complete one.

  **`prune` never deletes a git branch**, at any combination of flags. The
  working tree of a removed box goes; the branch holding its unreviewed work
  stays. `rm` and `prune --boxes` remove a box through one shared code path,
  so the two cannot come to disagree about what removal means.

  The full teardown is `agentbox prune --apply --boxes --running --state
  --images`; without `--apply`, prune still removes nothing.
- **Workspace-config trust.** Host-side `[hooks]` and
  `[[workspace.mounts]]` from a workspace config are refused (exit 77) until
  the file is reviewed and accepted with `agentbox trust` (`--show`,
  `--revoke`). The trust digest covers the `extends` chain and profiles in
  the workspace file; any edit invalidates it. `agentbox allow` re-records
  trust after its own explicitly requested rewrite. Read-only inspection
  commands and `--dry-run` proceed with a warning — that is how you review
  an untrusted config. `doctor` reports trust status.
- **Agent install.** `claude-code` is installed from Anthropic's official
  signed apt repository (`downloads.claude.ai`), with the release signing
  key's fingerprint verified at build time; `[agents].channel` selects the
  `stable` or `latest` apt suite. No implicit Node.js dependency for the
  agent, and no credentials in any image layer.
- **Governance.** `project.max_boxes`, cross-project `[limits]`, and idle
  handling that stops (never removes) a box.
- **`agentbox completion bash|zsh|fish`** prints completion scripts covering
  subcommands, flags, and dynamic box/bundle names.
- **Man pages:** `agentbox(1)`, `agentbox.toml(5)`, `agentbox-security(7)`
  (the last carrying the security property table).
- **Docs:** an install guide ([docs/install.md](docs/install.md)) and a set
  of copy-paste configuration examples
  ([docs/configuration-examples.md](docs/configuration-examples.md)),
  alongside the configuration and security references.

### Known gaps

- The Layer-3 filtered share needs `/dev/fuse` and a mount route — root, or
  the setuid `fusermount3` helper with `user_allow_other`; without either,
  `mask_mode = "auto"` resolves to `view` with a warning and an explicit
  `"filter"` is a config error naming why. The filtered share does not pass
  through extended attributes (`ENOSYS`).
- Proxy credential injection is not implemented.
- The `vm` tier's host-side mask view needs agentbox to run with
  `CAP_SYS_ADMIN`; without it, mask mounts are expressed in the guest and
  agentbox warns that a guest-root process could unmount them.
- `agentbox allow` does not preserve TOML comments (it says so when it runs).
- No published artifacts: agentbox is build-from-source only (see
  [docs/install.md](docs/install.md)). There are no tags, binaries, distro
  packages, or `go install` support, and none are planned right now.

[Unreleased]: https://github.com/sblmnl/agentbox/commits/main
