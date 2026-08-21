_nestwg() {
    local current previous command
    COMPREPLY=()
    current="${COMP_WORDS[COMP_CWORD]}"
    previous="${COMP_WORDS[COMP_CWORD-1]}"
    command="${COMP_WORDS[1]}"

    if (( COMP_CWORD == 1 )); then
        COMPREPLY=( $(compgen -W 'connect validate plan up attach detach down status diagnose exec shell doctor recover version' -- "$current") )
        return
    fi
    if [[ "$command" == attach && "$previous" == --route ]]; then
        return
    fi
    if [[ ( "$command" == connect || "$command" == up ) && "$previous" == --wait ]]; then
        COMPREPLY=( $(compgen -W '5s 10s 30s 1m' -- "$current") )
        return
    fi
    case "$command" in
        connect|validate|plan|up)
            COMPREPLY=( $(compgen -f -- "$current") )
            ;;
		attach)
			COMPREPLY=( $(compgen -W '--route' -- "$current") )
			;;
    esac
}
complete -F _nestwg nestwg
