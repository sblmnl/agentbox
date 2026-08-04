package app

import (
	"fmt"
	"os"
)

// CmdCompletion prints a completion script for the named shell. Box
// instance names and bundle names are completed dynamically by invoking
// agentbox itself, so the scripts never go stale against the project state.
func CmdCompletion(shell string) (int, error) {
	switch shell {
	case "bash":
		fmt.Print(completionBash)
	case "zsh":
		fmt.Print(completionZsh)
	case "fish":
		fmt.Print(completionFish)
	default:
		return 0, Usagef("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}
	// Diagnostics stay off stdout: the script is meant to be sourced.
	fmt.Fprintf(os.Stderr, "# add to your shell config, e.g. `agentbox completion %s > ~/.local/share/agentbox/completion.%s`\n", shell, shell)
	return 0, nil
}

const completionCommands = "run shell new attach default up stop down restart status ps logs build config mounts masks backends allow bundles init ls rm prune doctor trust completion version help"

const completionBash = `# bash completion for agentbox
_agentbox() {
    local cur prev words
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    words="` + completionCommands + `"
    local flags="-C --directory -w --workspace -n --name --new --all --tree-mode -p --profile -c --config --no-config -b --backend --min-isolation --force-isolation -e --env -E --env-passthrough --network --offline --rebuild --recreate --root --no-mask --dry-run --json -q --quiet -v --verbose --timeout -h --help"
    local ls_flags="--all --artifacts --json"
    local prune_flags="--apply --images --idle --boxes --running --state --json"

    _agentbox_boxes() {
        agentbox ls 2>/dev/null | awk 'NR>1 {sub(/\*$/,"",$2); print $2}'
    }
    _agentbox_bundles() {
        agentbox bundles 2>/dev/null | awk '{print $1}'
    }

    case "$prev" in
        -n|--name|attach|default|rm)
            COMPREPLY=( $(compgen -W "$(_agentbox_boxes)" -- "$cur") ); return ;;
        -b|--backend)
            COMPREPLY=( $(compgen -W "container vm" -- "$cur") ); return ;;
        --min-isolation|--force-isolation)
            COMPREPLY=( $(compgen -W "container vm" -- "$cur") ); return ;;
        --tree-mode)
            COMPREPLY=( $(compgen -W "auto shared worktree copy" -- "$cur") ); return ;;
        --network)
            COMPREPLY=( $(compgen -W "none proxy open" -- "$cur") ); return ;;
        --show)
            COMPREPLY=( $(compgen -W "$(_agentbox_bundles)" -- "$cur") ); return ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ); return ;;
        -C|--directory|-w|--workspace|-c|--config)
            COMPREPLY=( $(compgen -d -- "$cur") ); return ;;
    esac

    local i has_cmd=0 cmd=""
    for (( i=1; i < COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in -*) ;; *) has_cmd=1; cmd="${COMP_WORDS[i]}"; break ;; esac
    done
    if [[ "$cur" == -* ]]; then
        case "$cmd" in
            ls|status) COMPREPLY=( $(compgen -W "$ls_flags" -- "$cur") ) ;;
            prune)     COMPREPLY=( $(compgen -W "$prune_flags" -- "$cur") ) ;;
            *)         COMPREPLY=( $(compgen -W "$flags" -- "$cur") ) ;;
        esac
        return
    fi
    if (( ! has_cmd )); then
        COMPREPLY=( $(compgen -W "$words" -- "$cur") )
    else
        COMPREPLY=( $(compgen -c -- "$cur") )
    fi
}
complete -F _agentbox agentbox
`

const completionZsh = `#compdef agentbox
# zsh completion for agentbox

_agentbox_boxes() {
    local -a boxes
    boxes=(${(f)"$(agentbox ls 2>/dev/null | awk 'NR>1 {sub(/\*$/,"",$2); print $2}')"})
    _describe 'box' boxes
}
_agentbox_bundles() {
    local -a bundles
    bundles=(${(f)"$(agentbox bundles 2>/dev/null | awk '{print $1}')"})
    _describe 'bundle' bundles
}

_agentbox() {
    local -a commands
    commands=(
        'run:run a command in the box'
        'shell:interactive login shell in the box'
        'new:create an additional box without attaching'
        'attach:attach to an existing box'
        'default:set the project default box'
        'up:create and start the box; do not exec'
        'stop:stop a box, retaining state and tree'
        'down:stop and remove guest and networks; keep state'
        'restart:recreate the box with current configuration'
        'status:box state, backend, tier, policy, masks'
        'ps:processes running in the box'
        'logs:box or proxy logs; --denied filters refusals'
        'build:build or rebuild the image'
        'config:effective merged configuration'
        'mounts:every path presented to the guest and why'
        'masks:effective mask set'
        'backends:available backends and tiers'
        'allow:append domains to the workspace allowlist'
        'bundles:inspect built-in domain bundles'
        'init:scaffold agentbox.toml and .agentignore'
        'ls:boxes grouped by project'
        'rm:remove a box and its worktree'
        'prune:remove state for vanished workspaces'
        'doctor:preflight checks'
        'trust:trust the workspace config (hooks, mounts)'
        'completion:print a shell completion script'
        'version:tool and backend versions'
        'help:usage'
    )
    _arguments -C \
        '(-C --directory)'{-C,--directory}'[resolve the workspace as if from DIR]:directory:_directories' \
        '(-w --workspace)'{-w,--workspace}'[override workspace-root detection]:directory:_directories' \
        '(-n --name)'{-n,--name}'[address a box by name or ordinal]:box:_agentbox_boxes' \
        '--new[create an additional box]' \
        '--all[apply to every box in the project]' \
        '--tree-mode[tree mode]:mode:(auto shared worktree copy)' \
        '(-p --profile)'{-p,--profile}'[apply a profile overlay]:profile:' \
        '(-c --config)'{-c,--config}'[workspace configuration file]:file:_files' \
        '--no-config[built-in defaults only]' \
        '(-b --backend)'{-b,--backend}'[select a backend]:backend:(container vm)' \
        '--min-isolation[raise the isolation floor]:tier:(container vm)' \
        '--force-isolation[lower the floor (recorded, warned)]:tier:(container vm)' \
        '(-e --env)'{-e,--env}'[set KEY=VAL]:kv:' \
        '(-E --env-passthrough)'{-E,--env-passthrough}'[forward KEY from caller env]:key:' \
        '--network[network mode]:mode:(none proxy open)' \
        '--offline[same as --network none]' \
        '--rebuild[rebuild the image before starting]' \
        '--recreate[recreate the box before exec]' \
        '--root[exec as uid 0 in the guest]' \
        '--no-mask[skip masking (warns)]' \
        '--dry-run[print the plan; change nothing]' \
        '--json[machine-readable output]' \
        '(-q --quiet)'{-q,--quiet}'[less diagnostics]' \
        '(-v --verbose)'{-v,--verbose}'[more diagnostics]' \
        '--timeout[startup wait budget in seconds]:seconds:' \
        '1:command:->cmds' \
        '*::arg:->args'
    case $state in
        cmds) _describe 'command' commands ;;
        args)
            case $words[1] in
                attach|default|rm) _agentbox_boxes ;;
                ls) _arguments '--all[span every project]' '--artifacts[live state and everything each box holds]' ;;
                status) _arguments '--all[every box in the project]' '--artifacts[everything the box holds]' ;;
                prune) _arguments \
                    '--apply[actually reclaim]' \
                    '--images[also built images no box references]' \
                    '--idle[also boxes past their idle timeout (stopped, not removed)]' \
                    '--boxes[also stopped boxes: guest, networks, tree]' \
                    '--running[with --boxes, also boxes that are running]' \
                    '--state[with --boxes, also each box'"'"'s persistent home]' ;;
                completion) _values 'shell' bash zsh fish ;;
                trust) _arguments '--show[show trust status]' '--revoke[revoke trust]' ;;
                run) _command_names -e ;;
            esac ;;
    esac
}
_agentbox "$@"
`

const completionFish = `# fish completion for agentbox
function __agentbox_boxes
    agentbox ls 2>/dev/null | awk 'NR>1 {sub(/\*$/,"",$2); print $2}'
end
function __agentbox_bundles
    agentbox bundles 2>/dev/null | awk '{print $1}'
end
function __agentbox_no_subcommand
    not __fish_seen_subcommand_from ` + completionCommands + `
end

complete -c agentbox -n __agentbox_no_subcommand -a run -d 'run a command in the box'
complete -c agentbox -n __agentbox_no_subcommand -a shell -d 'interactive login shell in the box'
complete -c agentbox -n __agentbox_no_subcommand -a new -d 'create an additional box'
complete -c agentbox -n __agentbox_no_subcommand -a attach -d 'attach to an existing box'
complete -c agentbox -n __agentbox_no_subcommand -a default -d 'set the project default box'
complete -c agentbox -n __agentbox_no_subcommand -a up -d 'create and start; do not exec'
complete -c agentbox -n __agentbox_no_subcommand -a stop -d 'stop a box, retaining state'
complete -c agentbox -n __agentbox_no_subcommand -a down -d 'stop and remove guest; keep state'
complete -c agentbox -n __agentbox_no_subcommand -a restart -d 'recreate with current config'
complete -c agentbox -n __agentbox_no_subcommand -a status -d 'box state, backend, tier'
complete -c agentbox -n __agentbox_no_subcommand -a ps -d 'processes in the box'
complete -c agentbox -n __agentbox_no_subcommand -a logs -d 'box or proxy logs'
complete -c agentbox -n __agentbox_no_subcommand -a build -d 'build or rebuild the image'
complete -c agentbox -n __agentbox_no_subcommand -a config -d 'effective merged configuration'
complete -c agentbox -n __agentbox_no_subcommand -a mounts -d 'paths presented to the guest'
complete -c agentbox -n __agentbox_no_subcommand -a masks -d 'effective mask set'
complete -c agentbox -n __agentbox_no_subcommand -a backends -d 'available backends and tiers'
complete -c agentbox -n __agentbox_no_subcommand -a allow -d 'append to the allowlist'
complete -c agentbox -n __agentbox_no_subcommand -a bundles -d 'inspect domain bundles'
complete -c agentbox -n __agentbox_no_subcommand -a init -d 'scaffold agentbox.toml'
complete -c agentbox -n __agentbox_no_subcommand -a ls -d 'boxes grouped by project'
complete -c agentbox -n __agentbox_no_subcommand -a rm -d 'remove a box and its worktree'
complete -c agentbox -n __agentbox_no_subcommand -a prune -d 'reap vanished workspaces'
complete -c agentbox -n __agentbox_no_subcommand -a doctor -d 'preflight checks'
complete -c agentbox -n __agentbox_no_subcommand -a trust -d 'trust the workspace config'
complete -c agentbox -n __agentbox_no_subcommand -a completion -d 'print a completion script'
complete -c agentbox -n __agentbox_no_subcommand -a version -d 'versions'

complete -c agentbox -n '__fish_seen_subcommand_from attach default rm' -a '(__agentbox_boxes)'
complete -c agentbox -n '__fish_seen_subcommand_from bundles' -l show -a '(__agentbox_bundles)'
complete -c agentbox -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c agentbox -n '__fish_seen_subcommand_from trust' -l show -d 'show trust status'
complete -c agentbox -n '__fish_seen_subcommand_from trust' -l revoke -d 'revoke trust'
complete -c agentbox -n '__fish_seen_subcommand_from ls status' -l artifacts -d 'live state and everything each box holds'
complete -c agentbox -n '__fish_seen_subcommand_from prune' -l apply -d 'actually reclaim'
complete -c agentbox -n '__fish_seen_subcommand_from prune' -l images -d 'also images no box references'
complete -c agentbox -n '__fish_seen_subcommand_from prune' -l idle -d 'also idle boxes (stopped, not removed)'
complete -c agentbox -n '__fish_seen_subcommand_from prune' -l boxes -d 'also stopped boxes: guest, networks, tree'
complete -c agentbox -n '__fish_seen_subcommand_from prune' -l running -d 'with --boxes, also running boxes'
complete -c agentbox -n '__fish_seen_subcommand_from prune' -l state -d 'with --boxes, also persistent homes'

complete -c agentbox -s C -l directory -r -d 'resolve the workspace as if from DIR'
complete -c agentbox -s w -l workspace -r -d 'override workspace-root detection'
complete -c agentbox -s n -l name -x -a '(__agentbox_boxes)' -d 'address a box'
complete -c agentbox -l new -d 'create an additional box'
complete -c agentbox -l all -d 'apply to every box'
complete -c agentbox -l tree-mode -x -a 'auto shared worktree copy'
complete -c agentbox -s p -l profile -x -d 'profile overlay'
complete -c agentbox -s c -l config -r -d 'workspace configuration file'
complete -c agentbox -l no-config -d 'built-in defaults only'
complete -c agentbox -s b -l backend -x -a 'container vm'
complete -c agentbox -l min-isolation -x -a 'container vm'
complete -c agentbox -l force-isolation -x -a 'container vm'
complete -c agentbox -s e -l env -x -d 'set KEY=VAL'
complete -c agentbox -s E -l env-passthrough -x -d 'forward KEY'
complete -c agentbox -l network -x -a 'none proxy open'
complete -c agentbox -l offline -d 'same as --network none'
complete -c agentbox -l rebuild -d 'rebuild the image'
complete -c agentbox -l recreate -d 'recreate the box'
complete -c agentbox -l root -d 'exec as uid 0'
complete -c agentbox -l no-mask -d 'skip masking (warns)'
complete -c agentbox -l dry-run -d 'print the plan; change nothing'
complete -c agentbox -l json -d 'machine-readable output'
complete -c agentbox -s q -l quiet
complete -c agentbox -s v -l verbose
complete -c agentbox -l timeout -x -d 'startup wait budget (seconds)'
`
