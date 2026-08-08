# Security model

> **Experimental and educational — not for security-sensitive use.** agentbox
> is an unaudited personal project written without professional expertise in
> Go or low-level container/VM sandboxing, and its security reasoning has not
> been independently reviewed. The model described below is *design intent
> under active development*, not a vetted guarantee. Do not rely on it to
> contain untrusted or malicious code, or to protect real secrets. Assume
> escapes and mistakes are possible.

This page is required reading before running an agent unattended. It ships
with the tool as `agentbox-security(7)` and here.

## The honest claim

agentbox does **not** make it "safe" to run an agent unattended, and its two
isolation tiers are **not** equivalent.

The accurate claim is narrower: the blast radius of an agent mistake is
reduced to one workspace tree and one egress allowlist, both inspectable
beforehand (`agentbox mounts`, `masks`, `config --origin`, `--dry-run`) and
logged after (`logs --denied`). That is what makes skipping interactive
approval a defensible engineering decision rather than a reckless one. It is
not the same claim as safety, and the two tiers do not reduce that radius
equally.

## Threat model

**In scope.** An agent that is careless, overconfident, or acting on a
prompt injection from content it read. A workspace dependency with a
malicious install script attempting credential theft or exfiltration.
Accidental destruction outside the workspace. Under the `vm` tier,
additionally: an exploit achieving container escape.

**Out of scope.** Hypervisor escape. Under the `container` tier, kernel and
runtime escape. Side channels. A determined adversary who already has code
execution and specifically targets this configuration. Anything reachable
via the workspace's own git remote and CI credentials if those are mounted
in.

## Enforced properties by tier

| Property | container | vm |
|---|---|---|
| Kernel boundary | Shared with host | Private guest kernel |
| Escape class in scope | — | Container escape |
| Escape class out of scope | Kernel or runtime vulnerability | Hypervisor vulnerability |
| Guest root available | No, by construction | Optional, `[security.vm].guest_root` |
| Mask enforcement point | Host mount namespace | Host mount namespace or share daemon |
| Mask survives guest root | Not applicable | Yes |
| Mid-session file masked | No (`view`) | Yes (`filter`) |
| Nested container engine | Forbidden — equals host root | Permitted, guest-local |
| Capability restriction | `cap_drop: ALL` | Not applicable |
| Setuid removal | Yes | Yes (image property) |
| Read-only root | Yes | Guest-local, weaker meaning |
| Resource limits | Host cgroup, agent cannot raise | Guest-visible; a guest-root agent may raise in-guest limits |
| Egress control | Host-side sidecar proxy | Host-side proxy daemon over vsock |
| Inter-box reachability | Denied by network topology | Denied by network topology |
| Cross-box state access | Denied — separate volumes and mask views | Denied — separate disks and mask views |
| Startup cost | ~100 ms | seconds |
| Memory model | Shares host page cache | Private kernel and page cache |
| Requires KVM / nested virt | No | Yes |

> **Implementation status:** this release implements both tiers. The `vm`
> tier runs on an OCI-consuming VM runtime — Kata Containers, via docker;
> libkrun is [not usable](install.md#libkrun-is-not-usable) because nothing
> can enter a box it created — and requires `/dev/kvm`; where the runtime or KVM is
> missing, `min_isolation = "vm"` exits 69 naming what would fix it. The
> Layer 3 filtered share (`mask_mode = "filter"`) ships in this release:
> under `vm`, `auto` resolves to `filter` where the seam is deliverable
> (`/dev/fuse` present, plus either agentbox running as root or the setuid
> `fusermount3` helper with `user_allow_other` enabled — `agentbox doctor`
> reports which way `auto` resolves on this host) and falls back to `view`
> with a warning otherwise; an explicit `"filter"` that cannot be
> delivered is an error, never a downgrade. The host-side mask view
> likewise needs agentbox to run with CAP_SYS_ADMIN; without it, mask
> mounts are expressed in the guest and the degradation is warned about —
> never silent.

## Universal refusals

Under both tiers, agentbox refuses to construct a box with host networking,
a host PID namespace, a mounted host container-runtime socket, or
`seccomp: unconfined`. Any one of these makes the rest decorative; a mounted
host runtime socket in particular is equivalent to handing the agent root on
the host.

Boxes cannot reach one another, over the network or through shared state.
Each box gets its own network, its own persistent home, and its own mask
view: a project holding four boxes is four independent blast radii, not one
shared one. The single deliberate exception is `tree_mode = "shared"`, where
boxes see one working tree by explicit configuration — warned at creation,
because it is the one place the boundary between boxes is intentionally
porous.

## Masking, and its limits

Masking constructs the masked view of the workspace **on the host side** of
the filesystem boundary and presents that to the guest, so enforcement does
not depend on the guest's privilege level.

Under `view` mode, matched files read as empty and refuse writes; matched
directories appear empty, with writes landing in memory and never reaching
the host. Under `filter` mode (`vm` tier), the workspace is served by
agentbox's own share daemon — which may run unprivileged, mounting through
the setuid `fusermount3` helper, without weakening any of what follows: the
enforcement point is the daemon's position outside the guest, not the
privilege it holds. It evaluates the mask patterns at every
lookup: a masked path answers `ENOENT` and is omitted from directory
listings — indistinguishable from absence — and creating, linking, or
renaming onto a masked name is refused loudly (`EPERM`). Renaming a
directory that hides a masked entry is likewise refused (`EBUSY`), so an
anchored pattern cannot be dodged by moving an ancestor out from under it —
the same move `view` mode blocks because the masked path is a live
mountpoint. The daemon compiles its patterns from contents frozen host-side
at box start, so an agent editing `.agentignore` inside the box cannot
unmask anything.

What each mode guarantees:

| Guarantee | container + view | vm + view | vm + filter |
|---|---|---|---|
| Existing matched file unreadable | yes | yes | yes |
| Existing matched directory appears empty | yes | yes | yes |
| Matched path absent from listings | no | no | **yes** |
| Survives a root process in the guest | n/a — no guest root | yes | yes |
| File created after box start is masked | no | no | **yes** |
| Masked directory imposes no size cap | no | no | **yes** |
| Writes to masked paths never reach the host | yes | yes | yes |

Its documented limitations:

1. **Mounts are fixed at creation** (`view` mode only). A path that does not
   exist when the box is created cannot be masked; a `.env` the agent writes
   mid-session is readable. Under `filter` mode this does not apply: the
   filter is evaluated live, so a matching file is masked the moment it
   appears.
2. **A masked directory is a small writable ramdisk, not a hole** (`view`
   mode only). Masking a directory the toolchain builds into — `node_modules`,
   `obj/`, `.venv/` — fails the build once it exceeds
   `[masking].tmpfs_size`. Under `filter` mode this does not apply; there
   is no tmpfs, and a masked directory simply does not exist in the guest.
3. **`.git/` should not be masked.** It costs diff, commit, and history for
   almost no gain. `doctor` warns when a config does this.
4. **Anything in `[[workspace.mounts]]` bypasses masking** unless
   separately matched.
5. **Masking is not a secrets manager.** For credentials that need not sit
   in the tree at all, prefer `[variables.passthrough]` or keeping the
   secret host-side. Masking exists for the files an application genuinely
   needs on disk to run — a dev TLS key, a seeded database — where deleting
   them to run an agent would cost the ability to debug at all.

## Network policy

In the default `proxy` mode the guest has **no route to any external
address**; all egress goes through a policy proxy evaluating a default-deny
allowlist. The allowlist is a policy layer over a topology that already
denies, so a tool that ignores `HTTPS_PROXY` fails closed rather than
escaping. TLS is never intercepted — the proxy matches on the CONNECT
target, leaving certificate validation end-to-end. Every request, including
denials, is logged (`agentbox logs --denied`). `deny` entries are evaluated
first and win.

Known limitation: an HTTP CONNECT proxy cannot carry SSH. Git operations
must use HTTPS remotes in `proxy` mode; `doctor` detects SSH remotes rather
than leaving you to discover this mid-session.

### How the guest reaches the proxy

The two tiers place the proxy differently. Under `container` it is a sidecar
container straddling the box's internal network and an egress network. Under
`vm` it is a **host daemon reached over vsock**: a small forwarder inside the
box listens on loopback (that is what `HTTPS_PROXY` points at) and carries
the bytes to the daemon over the hypervisor's vsock channel. The box's own
network stays `--internal` and carries no egress at all.

vsock rather than the bridge, for a reason worth stating plainly: a VM
guest's path to a host process is ordinary IP traffic arriving at the host,
so it is subject to the host's `INPUT` policy and to any VPN kill-switch
filtering by source address. A default-deny `INPUT` chain, or a kill-switch
that treats only RFC 1918 as "local network", silently drops it — the box
comes up healthy and every network call inside it hangs. vsock carries no IP
address, crosses no bridge, and is not visible to netfilter, so egress
cannot be severed by host firewall or VPN state. The failure mode it
replaces was indistinguishable from a hung agent; if the path does break,
agentbox now fails the box at start naming the cause rather than letting it
hang.

Connections are attributed to a box by a per-box token, minted at create
time and never reused, so one shared listener cannot blur two boxes'
policies: a connection whose token matches no running box is closed without
being served. The audit log records the kernel-supplied peer context id
(`cid<n>`), which a guest cannot forge, in place of the client IP.

## Guest root

Under the `container` tier, guest root is denied by construction: no
`sudo`, setuid bits stripped, and `guest_root = "allow"` under
`[security.container]` is a **parse error**, not a setting. The reasoning: a
guest process with `CAP_SYS_ADMIN` could unmount a mask and read through it,
converting every mask from a boundary into a suggestion — silently, with no
error and no log line. Agents frequently want root to install packages; the
`vm` tier is where that request can be granted, because mask enforcement
lives outside the guest.

## Workspace config trust

`agentbox.toml` is committed, so cloning a repository and running `agentbox`
executes configuration you did not write. Host-side `[hooks]` (commands run
on **your host**) and `[[workspace.mounts]]` (which can mount `~/.ssh` into
the guest) are refused until the file has been reviewed and accepted with
`agentbox trust`. Any edit to the file — or to anything it `extends` —
invalidates the trust record. Inspection commands (`config`, `mounts`,
`doctor`, …) still work against an untrusted config; they are how you review
it.

## No silent divergence

One configuration file drives two non-equivalent boundaries, so divergence
must be loud:

1. `status` prints the active backend, tier, and mask mode on every
   invocation.
2. `doctor` names each unavailable backend and why.
3. This property table ships in the documentation (`agentbox-security(7)`
   and here), not buried in code.
4. Backend-specific keys are scope-checked **statically** — a
   `[security.container]` key at the wrong level fails identically on every
   machine, regardless of which backend is active.
5. `min_isolation` is honored without downgrade. Neither silent nor warned
   downgrade occurs; lowering requires `--force-isolation`, which is
   recorded in the box's metadata, flagged by `status` and `ls`, and warned
   about on every invocation.

The failure mode defended against is concrete: a developer writes and
verifies a configuration on a bare-metal workstation, a teammate runs it
inside a cloud VM, and the boundary silently becomes weaker while every
command still succeeds. Every rule above exists to make that impossible or
loud.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) in the repository root.
