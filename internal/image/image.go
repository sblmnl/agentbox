// Package image implements image resolution: the feature digest and
// the generated Dockerfile. Both backends consume the same OCI images; the
// backend never participates in the feature digest.
package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sblmnl/agentbox/internal/config"
)

// GeneratorVersion participates in the feature digest so that generator
// changes produce new tags.
const GeneratorVersion = "2"

// Features is the canonical input to the digest.
type Features struct {
	Base             string            `json:"base"`
	Toolchains       map[string]string `json:"toolchains"`
	Packages         []string          `json:"packages"`
	Agents           []string          `json:"agents"`
	BuildArgs        map[string]string `json:"build_args"`
	GeneratorVersion string            `json:"generator_version"`
}

// FeaturesFrom extracts digest-relevant features from the configuration.
// Toolchains set to "none" are absent.
func FeaturesFrom(cfg *config.Config) Features {
	tc := map[string]string{}
	for k, v := range cfg.Toolchains {
		if v != "" && v != "none" {
			tc[k] = v
		}
	}
	pkgs := append([]string{}, cfg.Image.Packages...)
	sort.Strings(pkgs)
	agents := append([]string{}, cfg.Agents.Install...)
	sort.Strings(agents)
	args := map[string]string{}
	for k, v := range cfg.Image.BuildArgs {
		args[k] = v
	}
	return Features{
		Base:             cfg.Image.Base,
		Toolchains:       tc,
		Packages:         pkgs,
		Agents:           agents,
		BuildArgs:        args,
		GeneratorVersion: GeneratorVersion,
	}
}

// Digest returns sha256(canonical_json(features))[0:16]. encoding/json
// serializes map keys in sorted order, which provides the canonical form.
func (f Features) Digest() string {
	blob, err := json.Marshal(f)
	if err != nil {
		panic(err) // static struct, cannot fail
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])[:16]
}

// Tag returns "agentbox/dev:<digest16>".
func (f Features) Tag() string { return "agentbox/dev:" + f.Digest() }

// Resolution describes how the image reference was chosen: ref
// verbatim, published, cached, a local build of the generated Dockerfile, or
// a local build of a user-supplied Dockerfile.
type Resolution struct {
	Ref      string   `json:"ref"`
	Source   string   `json:"source"` // "config-ref" | "published" | "cached" | "build" | "dockerfile"
	Warnings []string `json:"warnings,omitempty"`
}

// LocalBuild reports whether the reference must be built on this host before a
// box can be created, as opposed to pulled from a registry.
func (r Resolution) LocalBuild() bool { return r.Source == "build" || r.Source == "dockerfile" }

// Resolve picks the image reference. Precedence: an explicit [image].ref is
// used verbatim; otherwise a user-supplied [image].dockerfile is built as-is;
// otherwise agentbox builds its generated Dockerfile. In the first two cases
// declared toolchains are ignored (the referenced image or the Dockerfile must
// provide them), matching the "you own the image" contract.
func Resolve(cfg *config.Config) Resolution {
	if cfg.Image.Ref != "" {
		res := Resolution{Ref: cfg.Image.Ref, Source: "config-ref"}
		if cfg.Image.Dockerfile != "" {
			res.Warnings = append(res.Warnings,
				"both [image].ref and [image].dockerfile are set: ref takes precedence and the dockerfile is ignored")
		}
		if n := len(FeaturesFrom(cfg).Toolchains); n > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"[image].ref is set: the %d declared toolchain(s) are ignored; the referenced image must already provide them", n))
		}
		return res
	}
	if cfg.Image.Dockerfile != "" {
		res := Resolution{Source: "dockerfile"}
		digest, err := hashDockerfileFile(cfg.Image.Dockerfile)
		if err != nil {
			// The file may not exist yet at planning time; tag off its path so
			// the plan stays stable and warn. The build reads it authoritatively
			// and fails there if it is still missing.
			sum := sha256.Sum256([]byte("dockerfile-path\x00" + cfg.Image.Dockerfile))
			digest = hex.EncodeToString(sum[:])[:16]
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"[image].dockerfile %q could not be read (%v); it must exist and be readable at build time", cfg.Image.Dockerfile, err))
		}
		res.Ref = "agentbox/dev:" + digest
		if n := len(FeaturesFrom(cfg).Toolchains); n > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"[image].dockerfile is set: the %d declared toolchain(s) are ignored; your Dockerfile must install them", n))
		}
		return res
	}
	// Published/cached lookups are backend responsibilities at run time;
	// the plan defaults to a local build of the digest tag.
	return Resolution{Ref: FeaturesFrom(cfg).Tag(), Source: "build"}
}

// DockerfileDigest returns the 16-hex tag suffix for a user-supplied
// Dockerfile's contents, so editing the file produces a new tag and a rebuild.
func DockerfileDigest(content []byte) string {
	sum := sha256.Sum256(append([]byte("dockerfile\x00"), content...))
	return hex.EncodeToString(sum[:])[:16]
}

func hashDockerfileFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return DockerfileDigest(data), nil
}

// Verified apt signing-key fingerprints: fetching a key and
// immediately trusting it is not verification, so fingerprints are compiled
// in and the build fails on mismatch.
var repoKeyFingerprints = map[string]string{
	"nodesource":  "6F71F525282841EEDAF851B42F59B5F99B1BE0B4",
	"claude-code": "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE",
}

// Dockerfile generates the image build file.
func Dockerfile(cfg *config.Config, uid, gid int) string {
	f := FeaturesFrom(cfg)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# generated by agentbox (generator v%s); feature digest %s", GeneratorVersion, f.Digest())
	w("# regenerate with `agentbox build`; do not edit")
	w("FROM %s", cfg.Image.Base)
	w("")
	w("ARG AGENTBOX_UID=%d", uid)
	w("ARG AGENTBOX_GID=%d", gid)
	// guest root is the one image property that varies by tier; it is
	// a build arg so the feature digest stays backend-independent.
	w("ARG AGENTBOX_GUEST_ROOT=deny")
	for _, k := range sortedKeys(cfg.Image.BuildArgs) {
		w("ARG %s=%q", k, cfg.Image.BuildArgs[k])
	}
	w("")
	w("ENV DEBIAN_FRONTEND=noninteractive")

	// Baseline agent tooling regardless of toolchains. gnupg is part of the
	// baseline because every apt-repo step below verifies a signing-key
	// fingerprint with gpg before trusting it, and no supported base image
	// ships gnupg.
	base := []string{"git", "ripgrep", "fd-find", "jq", "curl", "less", "tmux", "sqlite3", "unzip", "ca-certificates", "gnupg", "openssh-client", "locales"}
	pkgs := append(base, cfg.Image.Packages...)
	sort.Strings(pkgs)
	w("RUN apt-get update && apt-get install -y --no-install-recommends \\")
	w("      %s \\", strings.Join(pkgs, " "))
	w("    && rm -rf /var/lib/apt/lists/* \\")
	w("    && (ln -sf $(command -v fdfind) /usr/local/bin/fd || true)")
	w("")

	// Non-root user matching the invoking uid/gid, reclaiming any existing
	// uid in the base image (Ubuntu ships `ubuntu` at 1000).
	w("RUN set -eu; \\")
	w("    existing=$(getent passwd \"$AGENTBOX_UID\" | cut -d: -f1 || true); \\")
	w("    if [ -n \"$existing\" ] && [ \"$existing\" != agent ]; then userdel -r \"$existing\" 2>/dev/null || userdel \"$existing\"; fi; \\")
	w("    getent group \"$AGENTBOX_GID\" >/dev/null || groupadd -g \"$AGENTBOX_GID\" agent; \\")
	w("    useradd -m -u \"$AGENTBOX_UID\" -g \"$AGENTBOX_GID\" -s /bin/bash agent")
	w("")

	// No sudo when the active tier is container; optional under vm.
	w("RUN set -eu; \\")
	w("    if [ \"$AGENTBOX_GUEST_ROOT\" = allow ]; then \\")
	w("      apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*; \\")
	w("      echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent; \\")
	w("    else \\")
	w("      apt-get purge -y sudo 2>/dev/null || true; \\")
	w("    fi")
	w("")

	for _, name := range sortedKeys(f.Toolchains) {
		writeToolchain(w, name, f.Toolchains[name])
	}

	// Toolchain caches and global prefixes under the persistent home.
	// No PIPX_*: pipx is not installed. `uv tool install` covers it, and uv
	// already defaults to ~/.local/bin, which is on PATH below.
	w("ENV NPM_CONFIG_PREFIX=/home/agent/.npm-global \\")
	w("    UV_CACHE_DIR=/home/agent/.cache/uv \\")
	w("    NUGET_PACKAGES=/home/agent/.nuget/packages \\")
	w("    DOTNET_BUNDLE_EXTRACT_BASE_DIR=/home/agent/.cache/dotnet-bundle \\")
	w("    PATH=/home/agent/.npm-global/bin:/home/agent/.local/bin:$PATH")
	w("")

	// Telemetry opt-outs and self-updater disables: a read-only root turns
	// a self-update attempt into a confusing crash.
	w("ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \\")
	w("    DOTNET_NOLOGO=1 \\")
	w("    npm_config_update_notifier=false \\")
	w("    NO_UPDATE_NOTIFIER=1 \\")
	w("    HOMEBREW_NO_ANALYTICS=1 \\")
	w("    DO_NOT_TRACK=1 \\")
	w("    CLAUDE_CODE_DISABLE_AUTOUPDATER=1 \\")
	w("    DISABLE_AUTOUPDATER=1")
	w("")

	for _, agent := range f.Agents {
		writeAgent(w, agent, cfg.Agents.Channel)
	}

	w("RUN git config --system --add safe.directory '*'")
	w("")
	if cfg.Security.StripSetuid {
		w("# [security].strip_setuid: remove setuid/setgid bits filesystem-wide")
		w("RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true")
		w("")
	}
	w("USER agent")
	w("WORKDIR /home/agent")
	w("CMD [\"bash\", \"-l\"]")
	return b.String()
}

func writeToolchain(w func(string, ...any), name, version string) {
	switch name {
	case "node":
		fp := repoKeyFingerprints["nodesource"]
		w("# toolchain: node %s (nodesource repo, signing key fingerprint verified)", version)
		w("RUN set -eu; \\")
		w("    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /tmp/ns.key; \\")
		w("    gpg --dearmor < /tmp/ns.key > /usr/share/keyrings/nodesource.gpg; \\")
		w("    actual=$(gpg --show-keys --with-fingerprint --with-colons /tmp/ns.key | awk -F: '/^fpr/{print $10; exit}'); \\")
		w("    [ \"$actual\" = %q ] || { echo \"nodesource key fingerprint mismatch: $actual\" >&2; exit 1; }; \\", fp)
		w("    echo \"deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_%s.x nodistro main\" > /etc/apt/sources.list.d/nodesource.list; \\", version)
		w("    apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*")
	case "python":
		// uv owns the interpreter outright and no distro python is installed
		// beside it. A second python on PATH is what let a failed install
		// pass for success: `python3` answered, from the distro, at a version
		// nobody asked for. With one interpreter, a broken install is a
		// missing command instead of a silent downgrade.
		//
		// /opt, not a home directory: the build runs as root, the box runs as
		// `agent`, and /home/agent is a persistent volume that shadows the
		// image after first creation — either would install it out of reach.
		w("# toolchain: python %s via uv (sole interpreter; no distro python alongside)", version)
		w("RUN set -eu; \\")
		w("    curl -fsSL https://astral.sh/uv/install.sh -o /tmp/uv.sh; \\")
		w("    env UV_INSTALL_DIR=/usr/local/bin INSTALLER_NO_MODIFY_PATH=1 sh /tmp/uv.sh; \\")
		w("    env UV_PYTHON_INSTALL_DIR=/opt/uv/python UV_PYTHON_BIN_DIR=/usr/local/bin \\")
		w("      /usr/local/bin/uv python install --default %s; \\", version)
		w("    chmod -R a+rX /opt/uv; \\")
		// Fail the build, not the box: assert the interpreter on PATH is the
		// requested one rather than something a dependency dragged in.
		w("    got=$(python3 --version); \\")
		w("    case \"$got\" in \"Python %s\"*) ;; \\", version)
		w("      *) echo \"python: wanted %s, got $got\" >&2; exit 1;; esac", version)
		w("ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python")
	case "dotnet":
		// The distro archive, not packages.microsoft.com: Microsoft ships no
		// .NET SDK there for Ubuntu >= 22.04 and points at the distro feed
		// instead, so no third-party repo or trust anchor is added here.
		w("# toolchain: dotnet %s (distro archive; Microsoft ships no SDK for this release)", version)
		w("RUN apt-get update \\")
		w("    && apt-get install -y --no-install-recommends dotnet-sdk-%s.0 \\", version)
		w("    && rm -rf /var/lib/apt/lists/*")
	case "go":
		w("# toolchain: go %s (official tarball, checksum verified against dl.google.com)", version)
		w("RUN set -eu; \\")
		w("    v=%s; arch=$(dpkg --print-architecture); \\", version)
		w("    curl -fsSL \"https://dl.google.com/go/go${v}.linux-${arch}.tar.gz\" -o /tmp/go.tgz; \\")
		w("    curl -fsSL \"https://dl.google.com/go/go${v}.linux-${arch}.tar.gz.sha256\" -o /tmp/go.sha; \\")
		w("    echo \"$(cat /tmp/go.sha)  /tmp/go.tgz\" | sha256sum -c -; \\")
		w("    tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz")
		w("ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local")
	case "rust":
		w("# toolchain: rust %s (rustup with fixed toolchain, self-update disabled)", version)
		w("RUN set -eu; \\")
		w("    curl -fsSL https://sh.rustup.rs -o /tmp/rustup.sh; \\")
		w("    env RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo sh /tmp/rustup.sh -y --no-modify-path --default-toolchain %s --profile minimal; \\", version)
		w("    ln -s /opt/cargo/bin/* /usr/local/bin/")
		w("ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/home/agent/.cargo")
	default:
		w("# toolchain: %s %s — no installer known to this generator version", name, version)
		w("RUN echo \"agentbox: unsupported toolchain %s\" >&2 && exit 1", name)
	}
	w("")
}

// AgentForCommand maps the command a user types to the [agents].install entry
// that provides it. It exists so that "the file claude was not found" can be
// answered with the one line that fixes it: the two names differ, and
// `[network].bundles = ["agent:claude-code"]` -- which only opens egress --
// looks near enough to `[agents].install = ["claude-code"]` to be mistaken
// for it.
func AgentForCommand(cmd string) (string, bool) {
	agent, ok := agentCommands[cmd]
	return agent, ok
}

var agentCommands = map[string]string{
	"claude": "claude-code",
}

func writeAgent(w func(string, ...any), agent, channel string) {
	switch agent {
	case "claude-code":
		fp := repoKeyFingerprints["claude-code"]
		// [agents].channel selects the apt suite: "latest" ships every release,
		// "stable" trails by ~a week. gpg comes from the baseline package set.
		suite := "stable"
		if channel == "latest" {
			suite = "latest"
		}
		w("# agent: claude-code (official apt repo, signing key fingerprint verified; no credentials in any layer)")
		w("RUN set -eu; \\")
		w("    install -d -m 0755 /etc/apt/keyrings; \\")
		w("    curl -fsSL https://downloads.claude.ai/keys/claude-code.asc -o /etc/apt/keyrings/claude-code.asc; \\")
		w("    actual=$(gpg --show-keys --with-fingerprint --with-colons /etc/apt/keyrings/claude-code.asc | awk -F: '/^fpr/{print $10; exit}'); \\")
		w("    [ \"$actual\" = %q ] || { echo \"claude-code key fingerprint mismatch: $actual\" >&2; exit 1; }; \\", fp)
		w("    echo \"deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/%s %s main\" > /etc/apt/sources.list.d/claude-code.list; \\", suite, suite)
		w("    apt-get update && apt-get install -y --no-install-recommends claude-code && rm -rf /var/lib/apt/lists/*")
	default:
		w("# agent: %s — no installer known to this generator version", agent)
		w("RUN echo \"agentbox: unsupported agent %s\" >&2 && exit 1", agent)
	}
	w("")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
