# Versioning and compatibility

agentbox follows [Semantic Versioning 2.0.0](https://semver.org/):
`MAJOR.MINOR.PATCH`. This page defines **what that promise covers** — the
public contract a version number is a statement about — and lays out a
concrete plan for **interrogating a candidate version for breaking changes**
before it ships, so the version bump is never smaller than the change
deserves.

The current version is `0.0.1-dev`; nothing has been published yet. The
pre-1.0 rules in [Pre-1.0](#pre-10-0yz) apply until the first `1.0.0`.

## What SemVer means for agentbox

agentbox is a **CLI tool, not a Go library** — all code lives under
`internal/` and `cmd/`, so there is no importable API to version. The public
contract is therefore the *observable behavior of the command and its
configuration*, in these surfaces:

### The public contract (covered by SemVer)

| Surface | What's promised | Canonical source of truth |
|---|---|---|
| **Subcommands** | The set of reserved subcommands and what each does. Adding one is breaking — it reinterprets a bare word that previously ran *in the box* as an agentbox command. | `reserved` (`cmd/agentbox/main.go`) |
| **Flags** | Global and per-command flags: their names, arity, and meaning. | flag parser (`cmd/agentbox/main.go`) |
| **Exit codes** | The numeric value and meaning of each agentbox-owned code (64/69/70/77/78) and the "in-box code passed through verbatim" rule. | `Ex*` consts (`internal/app/app.go`) |
| **Config schema** | Every `agentbox.toml` key: its path, type, allowed values, backend scope, and the "unknown keys are hard errors" rule. | `schema` map (`internal/config/schema.go`) |
| **Egress bundles** | Bundle names and the endpoint set each expands to. See [the bundle rule](#egress-bundles-a-special-case). | `Bundles` (`internal/netpol/netpol.go`) |
| **Security properties** | Every property in the `agentbox-security(7)` table: isolation floors, universal refusals, masking guarantees, trust. | `docs/security.md`, `docs/man/agentbox-security.7` |
| **stdout/stderr split** | Diagnostics go to stderr; stdout belongs to the in-box command. | architecture invariant |
| **On-disk state layout** | The XDG layout and the `BoxMeta` metadata schema, so an upgraded agentbox reads boxes an older one created. | `internal/state` |
| **Documented behavior** | Anything asserted in `README.md`, `docs/*.md`, or the man pages. "Documented behavior is the contract." | those files |

### Not part of the contract (may change in any release)

- Anything under `internal/` as a **Go API** — there is none to import.
- The **exact text** of generated artifacts: the generated Dockerfile, the
  generated squid config, log phrasing, diagnostic wording. Their *effect*
  is contracted (a masked file is unreadable; denied egress is denied);
  their bytes are not. The image **feature digest** is *expected* to change
  when inputs change — that is the mechanism, not a breakage.
- Timing, performance, and box **names/ids** chosen by heuristics.
- Behavior explicitly documented as unstable or "planned".

### MAJOR / MINOR / PATCH

- **MAJOR** — a backward-incompatible change to any covered surface: a
  removed/renamed subcommand or flag, a removed or retyped config key, a
  narrowed enum, an exit-code change, a **weakened security property**, an
  incompatible state-layout change, or a newly reserved subcommand.
- **MINOR** — backward-compatible additions: a new subcommand *(see the
  reserved-word caveat — it is additive to agentbox but can shadow an in-box
  command, so it is treated as breaking; prefer names unlikely to collide)*,
  a new optional config key, a new flag, a new bundle, a new toolchain/agent
  installer, a widened egress bundle (with the mandatory note below).
- **PATCH** — bug fixes and doc changes that touch no covered surface.

A **weakening of any enforced property** (masking, egress, isolation floor,
inter-box separation) is always MAJOR *and* loud, per the project's
"no silent weakening" invariant — it can never be a PATCH.

### Pre-1.0 (`0.y.z`)

Until `1.0.0`, SemVer permits breaking changes in **MINOR** bumps. agentbox
uses the standard `0.y.z` reading:

- Breaking change → bump **MINOR** (`0.Y.0`).
- Backward-compatible change or fix → bump **PATCH** (`0.y.Z`).

The **configuration schema is only frozen at 1.0** (as stated in the
changelog header): before then, keys may be renamed or retyped in a MINOR
bump. The interrogation process below **still runs pre-1.0** — breaking
changes are permitted, but they must be *detected, classified, and
disclosed*, never silent. Only the required-bump arithmetic differs.

### Egress bundles: a special case

Bundles are a security surface, not just an API surface. Regardless of
SemVer level:

- **Widening** a bundle (adding endpoints) widens every user's egress the
  moment they upgrade. It is at least a MINOR change and **must** carry an
  explicit release-note entry naming the bundle and the added endpoints.
- **Removing or renaming** a bundle, or **narrowing** it (dropping endpoints
  a workflow may depend on), is breaking (MAJOR at ≥1.0).

The interrogation gate enforces both the classification *and* the presence
of the changelog note for widenings.

### Deprecation policy

Prefer deprecation over removal. A deprecated flag, key, or subcommand:

1. Keeps working for **at least one MINOR release** (one `0.Y` pre-1.0).
2. Emits a warning to **stderr** on every use, naming the replacement.
3. Is recorded under a `Deprecated` heading in the release notes.
4. Is removed no earlier than the next MAJOR (or next MINOR pre-1.0), and
   the removal is itself a breaking-change entry.

Where practical, a removed name becomes an **alias** that forwards with a
warning rather than a hard error (as `ultrareview` → `code-review ultra`
does elsewhere in the ecosystem).

## Where the version lives, and the release flow

The canonical version string is `ToolVersion` in `internal/app/app.go`
(printed by `agentbox version`). The `Makefile` derives a build-time version
from `git describe`; a release keeps the two in sync. Releasing is:

1. Run the [breaking-change interrogation](#interrogating-a-new-version)
   against the last released version; let it compute the **minimum required
   bump**.
2. Choose the new version ≥ that minimum.
3. Update `ToolVersion`, move the release notes' `[Unreleased]` section under
   the new `vX.Y.Z` heading with a date, and update the man-page `.TH`
   version fields.
4. Tag `vX.Y.Z` on GitHub. There is **no build or packaging pipeline** —
   agentbox is distributed as source only, so a tag is just a named commit
   users can check out and `make install`.
5. Snapshot the new contract manifest into the baseline set (step below), so
   the next cycle diffs against it.

## Interrogating a new version for breaking changes {#interrogating-a-new-version}

The goal: **mechanically detect every breaking change** between the working
tree and the last released version, classify it, and refuse to tag a release
whose version bump is smaller than the changes require. Automated where the
surface is machine-readable; a checklist where it is not.

### Principle: every contract surface has a machine-readable source of truth

The table in [The public contract](#the-public-contract-covered-by-semver)
is not just documentation — every row (except the two human-judgment ones)
points at an in-code value that can be serialized: the `schema` map, the
`reserved` set, the `Bundles` registry, the `Ex*`
consts, and the `BoxMeta` struct. That makes a **contract manifest**
possible: one canonical JSON document that fully describes the covered
surfaces at a given commit.

### 1. The contract manifest

A single generated `contract.json` capturing, in a stable, sorted form:

```jsonc
{
  "manifest_version": 1,
  "subcommands": ["allow", "attach", "backends", "..."],
  "flags": { "global": [...], "per_command": { "logs": ["--denied", "..."] } },
  "exit_codes": { "64": "usage", "69": "isolation-floor", "70": "software",
                  "77": "untrusted-config", "78": "invalid-config" },
  "config_schema": {
    "network.mode": { "kind": "string", "enum": ["none","proxy","open"], "scope": "neutral" },
    "security.vm.guest_root": { "kind": "string", "enum": ["allow","deny"], "scope": "vm" }
    // ... every key from the schema map
  },
  "bundles": { "npm": ["registry.npmjs.org"], "github": ["github.com", "..."] },
  "state": { "boxmeta_schema": 1, "layout": ["projects/<key>/boxes/<id>/meta.json", "..."] }
}
```

Security properties and free-form documented behavior are **not** encoded
here — they are covered by the [human-review checklist](#4-human-review-surfaces).

### 2. Generating the manifest

Serialize directly from the sources of truth. Because `schema` and the
subcommand sets are unexported, the cleanest generator is an **in-package
golden test** (it can read them without exporting anything):

- `internal/contract/contract_test.go` builds the manifest from
  `config.SchemaSpecs()`, `app.Subcommands()`, `netpol.Bundles`, the `Ex*`
  consts, and `state.BoxMetaSchema`, and writes `testdata/contract.json`
  under `-update`; without `-update` it asserts the committed file matches
  (so an un-regenerated manifest fails CI — the drift is loud).
- This adds **no new CLI subcommand** (which would itself be a contract
  change). If a runtime surface is later wanted, enrich `version --json`
  rather than adding a reserved word.

Helpers to add: `config.SchemaSpecs() map[string]Spec` and
`app.Subcommands() []string` are thin accessors over values that already
exist (the `schema` map). `netpol.Bundles` and the
`Ex*` consts are already exported. The one genuinely new value is an
explicit `state.BoxMetaSchema` version integer stamped into `BoxMeta` — the
struct exists but is not yet versioned, and versioning it is worth doing on
its own so an older agentbox can refuse a newer box's metadata cleanly.

### 3. Baselines and the diff

- Commit one baseline per released version: `testdata/contract/v0.1.0.json`,
  `testdata/contract/v0.2.0.json`, …
- `make contract-check` regenerates the HEAD manifest and **diffs it against
  the most recent released baseline**, classifying every delta:

| Surface | Delta | Classification |
|---|---|---|
| Subcommand | removed / renamed | **breaking** |
| Subcommand | added | **breaking** (reserved-word shadowing) — flagged for explicit sign-off |
| Flag | removed / renamed / arity change | **breaking** |
| Flag | added | additive |
| Exit code | value or meaning changed | **breaking** |
| Config key | removed / kind changed / enum narrowed / scope changed / newly required | **breaking** |
| Config key | added (optional) / enum widened | additive |
| Bundle | removed / renamed / narrowed | **breaking** |
| Bundle | widened (endpoints added) | additive **+ requires a release note** |
| Bundle | added | additive |
| State | `boxmeta_schema` incompatible bump / layout change | **breaking** |

### 4. The version-bump gate

`make contract-check` computes the **minimum required bump** = the
highest-severity delta (breaking → MAJOR, or MINOR pre-1.0; additive →
MINOR; none → PATCH). It then compares against the **proposed** next version
(from the release tag or a `NEXT_VERSION` input) and **fails** when the
proposed bump is too small, e.g.:

```
contract-check: FAIL
  config key removed: [resources.pids]           -> requires MAJOR
  bundle widened: npm (+registry.npmjs.example)  -> requires release note (missing)
  proposed: v0.2.1 (PATCH)  minimum: v0.3.0
```

For bundle widenings it additionally greps the diff hunk for a matching
release-note entry and fails if absent — enforcing the egress-disclosure
rule mechanically.

### 5. Human-review surfaces

Two surfaces resist full automation and get a **release checklist** item,
reviewed against the diff:

- **Security properties.** Did any change weaken a property in the
  `agentbox-security(7)` table (a relaxed universal refusal, a mask that no
  longer holds, a downgraded floor)? If so it is MAJOR and must be loud. The
  existing masking/egress/trust *refusal-path* tests are the first line of
  defense; the checklist is the second.
- **Documented behavior.** Did behavior documented in the README/docs/man
  pages change without those files changing? (A `git diff --stat` that
  touches `internal/` but not `docs/` on a behavior PR is a smell.)

### CI and release wiring

- **On every PR:** a `contract` job runs `make contract-check` against the
  latest released baseline in *annotate* mode — it comments the classified
  deltas so reviewers see "this PR is breaking" early. It also fails if the
  committed `testdata/contract.json` is stale.
- **On release (tag push):** `contract-check` runs as a **hard gate** with
  the tag as the proposed version; a too-small bump blocks the release.
- **After release:** the new manifest is snapshotted into
  `testdata/contract/vX.Y.Z.json` and committed.

This complements, not replaces, the existing golden tests for generated
outputs (mask sets, squid config, Dockerfile) — those catch *unintended*
drift in artifacts; the contract manifest catches *incompatible* changes in
the promised surface.

### Implementation checklist (phased)

1. Add the thin exported accessors (`SchemaSpecs`, `Subcommands`,
   `BoxMetaSchema`) and the in-package manifest generator + golden test.
2. Commit the first baseline (`testdata/contract/v0.0.1.json` at first tag).
3. Add `make contract` (regenerate) and `make contract-check` (diff +
   classify + gate).
4. Wire the PR annotate job and the release hard-gate into
   `.github/workflows/ci.yml`.
5. Add the security/docs items to a `RELEASING.md` checklist.

Until step 1 lands, the interrogation is the **manual** version of the same
process: diff the four source-of-truth locations by hand against the last
release and classify per the tables above. Documenting the surfaces here is
what makes that review tractable in the meantime.

## See also

- [docs/configuration.md](configuration.md) — the config schema this versions
- [docs/security.md](security.md) — the security properties this protects
- `agentbox-security(7)` — the property table under review each release
