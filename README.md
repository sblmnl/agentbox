# agentbox

> [!WARNING]
> **Experimental — not audited, and not for security-sensitive environments.**
> agentbox has not been independently reviewed, and it is under active
> development. Everything below about isolation, secret masking, and egress
> control describes *design intent*, not a guarantee. Do not rely on agentbox
> to contain untrusted or malicious code, to protect real secrets, or for
> anything where a sandbox escape would actually matter.

Run an agentic coding tool inside an isolated, per-project environment —
declarative config, default-deny egress, host-side secret masking,
disposable named boxes.

This repository holds the actual implementation intent of agentbox: the .NET
codebase here is where the tool is really being built, and it is the version
to follow. That does not soften the warning above — it is still unaudited,
still under active development, and still not something to rely on in
security-sensitive environments until it is.

> [!NOTE]
> The original Go prototype lives at
> [sblmnl/agentbox-prototype](https://github.com/sblmnl/agentbox-prototype).
> It works and is still useful — both as a reference for the behavior this
> implementation is converging on and as a record of how the design got here —
> but it is a historical artifact, not the path forward. New work happens in
> this repository.
