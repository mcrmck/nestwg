complete -c nestwg -f
complete -c nestwg -n '__fish_use_subcommand' -a help -d 'Show general or command-specific help'
complete -c nestwg -n '__fish_use_subcommand' -a validate -d 'Validate a chain and WireGuard files'
complete -c nestwg -n '__fish_use_subcommand' -a plan -d 'Print the pinned executable plan'
complete -c nestwg -n '__fish_use_subcommand' -a up -d 'Expose a nested VPN to host traffic'
complete -c nestwg -n '__fish_use_subcommand' -a down -d 'Remove host routing and the nested VPN'
complete -c nestwg -n '__fish_use_subcommand' -a status -d 'Show live chain status'
complete -c nestwg -n '__fish_use_subcommand' -a diagnose -d 'Check VPN and protected-route health'
complete -c nestwg -n '__fish_use_subcommand' -a doctor -d 'Check Linux networking prerequisites'
complete -c nestwg -n '__fish_use_subcommand' -a recover -d 'Remove process-free orphan VPN resources'
complete -c nestwg -n '__fish_use_subcommand' -a version -d 'Print the version'
complete -c nestwg -n '__fish_seen_subcommand_from up' -l wait -d 'Wait for every VPN hop to connect' -x
complete -c nestwg -n '__fish_seen_subcommand_from up' -l default-route -d 'Route supported address families through the VPN'
complete -c nestwg -n '__fish_seen_subcommand_from up' -l route -d 'Route a destination CIDR through the VPN' -x
complete -c nestwg -n '__fish_seen_subcommand_from up' -l isolated -d 'Construct the chain without host routing'
complete -c nestwg -n '__fish_seen_subcommand_from up down' -s v -l verbose -d 'Print lifecycle progress'
