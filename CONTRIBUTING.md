# Contributing to agentbox

Thanks for your interest. agentbox is a security-adjacent tool, so the bar
for changes is deliberate rather than fast — please read this before opening
a PR.

## Ground rules

- **Documented behavior is the contract.** What agentbox does is described
  in the README, the `docs/*.md` files, and the man pages under
  `docs/man/`. If your change diverges from documented behavior, say so
  explicitly in the PR and in the README's "deviations" list, and update
  the docs; divergence is acceptable, silence about it is not.
- **No silent weakening.** Anything that reduces an enforced property —
  masking, egress policy, isolation floor, inter-box separation — must be
  loud: an error, or a warning on every invocation. This is the review
  criterion applied most strictly.
- **One mask generator.** The ignore matcher and mask-set computation are
  shared code and differentially tested against
  `git check-ignore`. Do not fork or duplicate them; a second implementation
  doubles the surface for a silent failure to mask a secret.
- **Honest output.** Diagnostics to stderr, stdout belongs to the in-box
  command, exit codes per `sysexits.h` (69 = floor unsatisfied, 77 =
  untrusted config, 78 = invalid config).

## Development

```console
$ go build ./cmd/agentbox
$ go test ./...
$ make all            # gofmt check + vet + build + test
```

- Go ≥ 1.22. One external dependency (`BurntSushi/toml`); adding a
  dependency needs a strong justification.
- `gofmt` clean, `go vet` clean.
- The ignore-matcher conformance tests need `git` on `PATH`. The real-mount
  Layer-0 test needs root/`CAP_SYS_ADMIN`; it skips visibly elsewhere and
  runs in the privileged CI job.
- Tests that need a Docker daemon are excluded from `go test ./...` by
  design; keep unit coverage for the logic they exercise.

## Pull requests

1. One logical change per PR. Refactors separate from behavior changes.
2. New behavior comes with tests. For anything touching masking, egress, or
   trust, include a test that demonstrates the *refusal* path, not just the
   happy path.
3. Update the docs that restate the behavior you changed: README, the
   relevant `docs/*.md`, and the man pages under `docs/man/`.
4. Widening a network **bundle** widens every user's egress policy: bundle
   changes must appear in CHANGELOG.md with rationale.
5. Adding a reserved subcommand is a breaking change to the CLI contract —
   expect scrutiny of name collisions with common binaries.

## Reporting bugs

Use the issue templates. For anything security-sensitive — a way to read a
masked file, bypass the egress proxy, escape the workspace, or execute from
an untrusted config without trust — **do not open a public issue**; see
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree to release your contributions into the public
domain under [The Unlicense](LICENSE).
