---
name: Bug report
about: Something behaves differently than documented
labels: bug
---

<!--
Security-sensitive? A way to read a masked file, bypass the egress proxy,
cross between boxes, or run hooks from an untrusted config? DO NOT file it
here — use the private "Report a vulnerability" flow (see SECURITY.md).
-->

**What happened**

**What you expected** (cite the docs or man page if you can)

**Reproduction**

```console
$ agentbox ...
```

**Environment**

```console
$ agentbox version --json
$ agentbox doctor
```

**Relevant output** (`agentbox --verbose ...`, `agentbox config --origin`,
`agentbox mounts` as applicable)
