complete -c nestwg -f
complete -c nestwg -n '__fish_use_subcommand' -a validate -d 'Validate a chain and WireGuard files'
complete -c nestwg -n '__fish_use_subcommand' -a plan -d 'Print the pinned executable plan'
complete -c nestwg -n '__fish_use_subcommand' -a up -d 'Create a persistent nested VPN chain'
complete -c nestwg -n '__fish_use_subcommand' -a down -d 'Remove a chain'
complete -c nestwg -n '__fish_use_subcommand' -a status -d 'Show live chain status'
complete -c nestwg -n '__fish_use_subcommand' -a exec -d 'Run a command in a payload network'
complete -c nestwg -n '__fish_use_subcommand' -a shell -d 'Open a shell in a payload network'
complete -c nestwg -n '__fish_use_subcommand' -a doctor -d 'Check Linux networking prerequisites'
complete -c nestwg -n '__fish_use_subcommand' -a recover -d 'Remove process-free orphan namespaces'
complete -c nestwg -n '__fish_use_subcommand' -a version -d 'Print the version'
complete -c nestwg -n '__fish_seen_subcommand_from up' -l wait -d 'Wait for every hop to handshake' -x
