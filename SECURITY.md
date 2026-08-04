# Security policy

## What counts as a vulnerability here

agentbox's job is to bound what an agent can do. Anything that quietly
breaks a bound it claims to enforce is a vulnerability, including:

- Reading, listing, or writing through a **mask** (a path matched by
  `.agentignore` rules) from inside a box.
- **Egress** reaching a destination outside the effective allowlist in
  `proxy` mode, or any traffic bypassing the proxy topology.
- A box reaching another box's network endpoint, persistent home, tree
  (outside `shared` mode), or mask view.
- Escaping the workspace tree, or writing to the host outside the
  workspace and agentbox's own state directories.
- Executing `[hooks]` or materializing `[[workspace.mounts]]` from a
  workspace config that has **not** been trusted, or defeating trust
  invalidation.
- Silent isolation-floor downgrade, or any path where a weaker guarantee is
  substituted without an error or a per-invocation warning.

Things that are **documented limitations, not vulnerabilities** (see
[docs/security.md](docs/security.md)): files created after box start being
readable under `view` masking; `tmpfs_size` limits on masked directories;
kernel or runtime escape under the container tier; anything the threat
model explicitly places out of scope.

## Reporting

Please **do not open a public issue** for vulnerabilities. Use GitHub's
private vulnerability reporting ("Report a vulnerability" under the
Security tab of the repository). Include the agentbox version
(`agentbox version --json`), backend and runtime, a minimal reproduction,
and what boundary was crossed.

You can expect an acknowledgement within 7 days. Please allow up to 90 days
for a fix before public disclosure; we will credit reporters in the release
notes unless you prefer otherwise.

## Supported versions

Pre-1.0, only the latest release receives fixes. After 1.0, the latest
minor release of the current major version.
