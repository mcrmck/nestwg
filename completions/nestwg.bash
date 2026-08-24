_nestwg() {
    local current previous command
    COMPREPLY=()
    current="${COMP_WORDS[COMP_CWORD]}"
    previous="${COMP_WORDS[COMP_CWORD-1]}"
    command="${COMP_WORDS[1]}"

    if (( COMP_CWORD == 1 )); then
        COMPREPLY=( $(compgen -W 'help validate plan up down status diagnose doctor recover version' -- "$current") )
        return
    fi
    if [[ "$command" == up && "$previous" == --route ]]; then
        return
    fi
    if [[ "$command" == up && "$previous" == --wait ]]; then
        COMPREPLY=( $(compgen -W '5s 10s 30s 1m' -- "$current") )
        return
    fi
    case "$command" in
        validate|plan|down)
            COMPREPLY=( $(compgen -f -- "$current") )
            ;;
        up)
            COMPREPLY=( $(compgen -W '--help --wait --default-route --route --isolated --verbose -v' -- "$current") $(compgen -f -- "$current") )
            ;;
    esac
}
complete -F _nestwg nestwg
