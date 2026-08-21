#!/usr/bin/env bash
set -euo pipefail

readonly C0="nwg-c0"
readonly TRANSIT="nwg-lab-t1"
readonly TRANSIT2="nwg-lab-t2"
readonly PAYLOAD="nwg-lab-app"
readonly ENTRY="nwg-entry"
readonly EXIT="nwg-exit"
readonly DEST="nwg-dest"
readonly FINAL="nwg-final"
readonly ORPHAN_TRANSIT="nwg-orphan-t1"
readonly ORPHAN_PAYLOAD="nwg-orphan-app"
readonly BUSY_PAYLOAD="nwg-busy-app"
readonly NAMESPACES=("$C0" "$TRANSIT" "$TRANSIT2" "$PAYLOAD" "$ENTRY" "$EXIT" "$DEST" "$FINAL" "$ORPHAN_TRANSIT" "$ORPHAN_PAYLOAD" "$BUSY_PAYLOAD")
readonly UNDERLAY_NAMESPACES=("$C0" "$ENTRY" "$EXIT" "$DEST" "$FINAL")
readonly SETUP_FAILPOINTS=(
    recovery-state-saved
    resolver-saved
    namespace-created
    loopback-up
    wireguard-created
    wireguard-configured
    wireguard-moved
    mtu-set
    address-added
    wireguard-up
    route-added
    apply-complete
)

KEY_DIR=""

cleanup() {
    local namespace
    for namespace in "${NAMESPACES[@]}"; do
        ip netns delete "$namespace" 2>/dev/null || true
    done
    if [[ -n "$KEY_DIR" ]]; then
        rm -rf -- "$KEY_DIR"
    fi
}
trap cleanup EXIT INT TERM

fail() {
    echo "lab failure: $*" >&2
    exit 1
}

assert_lab_absent() {
    if ip netns list | grep -Eq '^nwg-lab-(t[0-9]+|app)([[:space:]]|$)'; then
        fail "failed setup leaked a lab namespace"
    fi
    if [[ -e /run/nestwg/lab.json || -e /run/nestwg/lab.resolv.conf ]]; then
        fail "failed setup leaked lab runtime state"
    fi
}

assert_lab_namespaces_present() {
    local namespace
    for namespace in "$TRANSIT" "$TRANSIT2" "$PAYLOAD"; do
        if [[ ! -e "/run/netns/$namespace" ]]; then
            fail "expected namespace $namespace is missing"
        fi
    done
}

generate_keypair() {
    local name="$1"
    wg genkey >"$KEY_DIR/$name.key"
    wg pubkey <"$KEY_DIR/$name.key" >"$KEY_DIR/$name.pub"
}

add_veth_pair() {
    local left_ns="$1"
    local left_name="$2"
    local right_ns="$3"
    local right_name="$4"

    ip link add "$left_name" type veth peer name "$right_name"
    ip link set "$left_name" netns "$left_ns"
    ip link set "$right_name" netns "$right_ns"
}

cleanup
KEY_DIR="$(mktemp -d)"
readonly KEY_DIR
umask 077
trap cleanup EXIT INT TERM

nestwg doctor

ip netns add "$ORPHAN_TRANSIT"
ip netns add "$ORPHAN_PAYLOAD"
nestwg recover orphan >/dev/null
if ip netns list | grep -q '^nwg-orphan-'; then
    fail "orphan recovery left chain namespaces behind"
fi

ip netns add "$BUSY_PAYLOAD"
ip netns exec "$BUSY_PAYLOAD" sleep 1 &
busy_process_pid=$!
sleep 0.1
if nestwg recover busy 2>/dev/null; then
    fail "recovery unexpectedly detached a namespace containing a process"
fi
wait "$busy_process_pid"
nestwg recover busy >/dev/null

for namespace in "${UNDERLAY_NAMESPACES[@]}"; do
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
done

# Physical client to entry underlay.
add_veth_pair "$C0" c0-entry "$ENTRY" entry-client
ip -n "$C0" address add 192.0.2.2/24 dev c0-entry
ip -n "$ENTRY" address add 192.0.2.1/24 dev entry-client
ip -n "$C0" link set c0-entry up
ip -n "$ENTRY" link set entry-client up
ip -n "$C0" route add default via 192.0.2.1

# Entry's public egress to the exit endpoint.
add_veth_pair "$ENTRY" entry-exit "$EXIT" exit-entry
ip -n "$ENTRY" address add 198.51.100.1/24 dev entry-exit
ip -n "$EXIT" address add 198.51.100.2/24 dev exit-entry
ip -n "$ENTRY" link set entry-exit up
ip -n "$EXIT" link set exit-entry up

# Middle relay's IPv6 egress to the final WireGuard endpoint.
add_veth_pair "$EXIT" exit-dest "$DEST" dest-exit
ip -n "$EXIT" -6 address add 2001:db8:2::1/64 dev exit-dest
ip -n "$DEST" -6 address add 2001:db8:2::2/64 dev dest-exit
ip -n "$EXIT" link set exit-dest up
ip -n "$DEST" link set dest-exit up
ip -n "$DEST" -6 route add default via 2001:db8:2::1

# Final relay's egress to the destination observed by application traffic.
add_veth_pair "$DEST" dest-final "$FINAL" final-dest
ip -n "$DEST" address add 203.0.114.1/24 dev dest-final
ip -n "$FINAL" address add 203.0.114.2/24 dev final-dest
ip -n "$DEST" link set dest-final up
ip -n "$FINAL" link set final-dest up
ip -n "$FINAL" route add default via 203.0.114.1

ip netns exec "$ENTRY" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$EXIT" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$EXIT" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec "$DEST" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$ENTRY" iptables -A FORWARD -i wg-entry-s -o entry-exit -j ACCEPT
ip netns exec "$ENTRY" iptables -A FORWARD -i entry-exit -o wg-entry-s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$ENTRY" iptables -t nat -A POSTROUTING -o entry-exit -j MASQUERADE

generate_keypair entry-server
generate_keypair entry-client
generate_keypair exit-server
generate_keypair exit-client
generate_keypair final-server
generate_keypair final-client

# Outer server at the entry.
ip -n "$ENTRY" link add wg-entry-s type wireguard
ip netns exec "$ENTRY" wg set wg-entry-s \
    private-key "$KEY_DIR/entry-server.key" \
    listen-port 51820 \
    peer "$(<"$KEY_DIR/entry-client.pub")" \
    allowed-ips 10.10.1.2/32
ip -n "$ENTRY" address add 10.10.1.1/24 dev wg-entry-s
ip -n "$ENTRY" link set wg-entry-s up

# Inner server at the exit.
ip -n "$EXIT" link add wg-exit-s type wireguard
ip netns exec "$EXIT" wg set wg-exit-s \
    private-key "$KEY_DIR/exit-server.key" \
    listen-port 51820 \
    peer "$(<"$KEY_DIR/exit-client.pub")" \
    allowed-ips 10.10.2.2/32,fd00:2::2/128
ip -n "$EXIT" address add 10.10.2.1/24 dev wg-exit-s
ip -n "$EXIT" -6 address add fd00:2::1/64 dev wg-exit-s
ip -n "$EXIT" link set wg-exit-s up
ip netns exec "$EXIT" iptables -A FORWARD -i wg-exit-s -o exit-dest -j ACCEPT
ip netns exec "$EXIT" iptables -A FORWARD -i exit-dest -o wg-exit-s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$EXIT" iptables -t nat -A POSTROUTING -o exit-dest -j MASQUERADE
ip netns exec "$EXIT" ip6tables -A FORWARD -i wg-exit-s -o exit-dest -j ACCEPT
ip netns exec "$EXIT" ip6tables -A FORWARD -i exit-dest -o wg-exit-s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Innermost server at the final relay.
ip -n "$DEST" link add wg-final-s type wireguard
ip netns exec "$DEST" wg set wg-final-s \
    private-key "$KEY_DIR/final-server.key" \
    listen-port 51820 \
    peer "$(<"$KEY_DIR/final-client.pub")" \
    allowed-ips 10.10.3.2/32,fd00:3::2/128
ip -n "$DEST" address add 10.10.3.1/24 dev wg-final-s
ip -n "$DEST" -6 address add fd00:3::1/64 dev wg-final-s
ip -n "$DEST" link set wg-final-s up
ip netns exec "$DEST" iptables -A FORWARD -i wg-final-s -o dest-final -j ACCEPT
ip netns exec "$DEST" iptables -A FORWARD -i dest-final -o wg-final-s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$DEST" iptables -t nat -A POSTROUTING -o dest-final -j MASQUERADE

cat >"$KEY_DIR/entry.conf" <<EOF
[Interface]
PrivateKey = $(<"$KEY_DIR/entry-client.key")
Address = 10.10.1.2/24

[Peer]
PublicKey = $(<"$KEY_DIR/entry-server.pub")
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5
EOF

cat >"$KEY_DIR/exit.conf" <<EOF
[Interface]
PrivateKey = $(<"$KEY_DIR/exit-client.key")
Address = 10.10.2.2/24, fd00:2::2/64

[Peer]
PublicKey = $(<"$KEY_DIR/exit-server.pub")
Endpoint = 198.51.100.2:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 5
EOF

cat >"$KEY_DIR/final.conf" <<EOF
[Interface]
PrivateKey = $(<"$KEY_DIR/final-client.key")
Address = 10.10.3.2/24, fd00:3::2/64

[Peer]
PublicKey = $(<"$KEY_DIR/final-server.pub")
Endpoint = [2001:db8:2::2]:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 5
EOF

cat >"$KEY_DIR/chain.yaml" <<EOF
apiVersion: nestwg.io/v1alpha1
kind: Chain
metadata:
  name: lab
spec:
  baseMTU: 1500
  dns:
    - 203.0.114.2
  hops:
    - name: entry
      wireguardConfig: $KEY_DIR/entry.conf
      outerFamily: ipv4
    - name: middle
      wireguardConfig: $KEY_DIR/exit.conf
      outerFamily: ipv4
    - name: exit
      wireguardConfig: $KEY_DIR/final.conf
      outerFamily: ipv6
EOF

cat >"$KEY_DIR/failure.yaml" <<EOF
apiVersion: nestwg.io/v1alpha1
kind: Chain
metadata:
  name: failure
spec:
  hops:
    - name: first
      wireguardConfig: $KEY_DIR/entry.conf
      outerFamily: ipv4
    - name: second
      wireguardConfig: $KEY_DIR/exit.conf
      outerFamily: ipv4
    - name: third
      wireguardConfig: $KEY_DIR/exit.conf
      outerFamily: ipv4
EOF

# A complete collision preflight must reject a foreign namespace before the
# first mutation or ownership record is created.
ip netns add nwg-failure-t2
if nsenter --net="/run/netns/$C0" nestwg up "$KEY_DIR/failure.yaml" 2>/dev/null; then
    fail "failure-injection chain unexpectedly came up"
fi
if ip netns list | grep -q '^nwg-failure-t1\b'; then
    fail "failed setup leaked its first transit namespace"
fi
if [[ -e /run/nestwg/failure.json || -e /run/nestwg/failure.resolv.conf ]]; then
    fail "failed setup leaked runtime state"
fi
ip netns delete nwg-failure-t2

# The lab binary alone includes environment-controlled failpoints. Every
# privileged setup stage must either complete or fully remove its reservation,
# resolver, interfaces, and namespaces. Release binaries omit these hooks.
for failpoint in "${SETUP_FAILPOINTS[@]}"; do
    if NESTWG_FAILPOINT="$failpoint" \
        nsenter --net="/run/netns/$C0" nestwg up "$KEY_DIR/chain.yaml" 2>/dev/null; then
        fail "setup failpoint $failpoint unexpectedly succeeded"
    fi
    assert_lab_absent
done

# If the operation and its automatic rollback both fail, the creating-phase
# reservation must remain and a normal `down` must finish recovery safely.
if NESTWG_FAILPOINT=wireguard-moved,rollback-delete-namespace \
    nsenter --net="/run/netns/$C0" nestwg up "$KEY_DIR/chain.yaml" 2>/dev/null; then
    fail "combined setup and rollback failure unexpectedly succeeded"
fi
if [[ ! -e /run/nestwg/lab.json || ! -e /run/nestwg/lab.resolv.conf ]]; then
    fail "incomplete rollback discarded its recovery record"
fi
assert_lab_namespaces_present
nestwg down lab
assert_lab_absent

# The primary terminal workflow must own the whole lifecycle: connect every
# hop, identify the VPN shell, carry traffic, and remove the VPN on shell exit.
# Remove keepalives first to prove that connect actively initiates handshakes.
for config in entry.conf exit.conf final.conf; do
    sed -i '/^PersistentKeepalive =/d' "$KEY_DIR/$config"
done
printf '%s\n' \
    'test "$NESTWG_VPN" = 1' \
    'test "$NESTWG_CHAIN" = lab' \
    'ip route get 203.0.114.2 | grep -q "dev nwg2"' \
    'ping -c 1 -W 2 203.0.114.2 >/dev/null' \
    | SHELL=/bin/sh nsenter --net="/run/netns/$C0" nestwg connect "$KEY_DIR/chain.yaml"
assert_lab_absent
for config in entry.conf exit.conf final.conf; do
    printf '\nPersistentKeepalive = 5\n' >>"$KEY_DIR/$config"
done

# NestWG creates all clients, placing each interface one network layer inward
# while its encrypted UDP socket remains in its birth namespace.
nsenter --net="/run/netns/$C0" nestwg up --wait 10s "$KEY_DIR/chain.yaml"
nestwg status lab
nestwg exec lab -- grep -qx 'nameserver 203.0.114.2' /etc/resolv.conf
nobody_home="$(getent passwd 65534 | cut -d: -f6)"
EXPECTED_HOME="$nobody_home" SUDO_UID=65534 SUDO_GID=65534 \
    nestwg exec lab -- sh -c 'test "$(id -u)" = 65534 && test "$HOME" = "$EXPECTED_HOME"'
nestwg exec lab -- sleep 1 &
payload_process_pid=$!
sleep 0.1
if nestwg down lab 2>/dev/null; then
    fail "down unexpectedly detached a chain with a running payload process"
fi
wait "$payload_process_pid"

ip -n "$PAYLOAD" link show dev nwg2 >/dev/null
if ip -n "$PAYLOAD" link show type veth | grep -q .; then
    fail "payload namespace unexpectedly contains a veth escape path"
fi

ENTRY_CAPTURE="$KEY_DIR/entry.pcap"
MIDDLE_CAPTURE="$KEY_DIR/middle.pcap"
EXIT_CAPTURE="$KEY_DIR/exit.pcap"
EXIT_UNDERLAY_CAPTURE="$KEY_DIR/exit-underlay.pcap"

ip netns exec "$ENTRY" timeout 5 tcpdump -qnni wg-entry-s \
    -c 1 'udp and host 198.51.100.2' -w "$ENTRY_CAPTURE" &
entry_capture_pid=$!
ip netns exec "$EXIT" timeout 5 tcpdump -qnni wg-exit-s \
    -c 1 'ip6 and udp and host 2001:db8:2::2' -w "$MIDDLE_CAPTURE" &
middle_capture_pid=$!
ip netns exec "$DEST" timeout 5 tcpdump -qnni wg-final-s \
    -c 1 'host 203.0.114.2' -w "$EXIT_CAPTURE" &
exit_capture_pid=$!
ip netns exec "$EXIT" timeout 5 tcpdump -qnni exit-entry \
    -c 1 'udp port 51820' -w "$EXIT_UNDERLAY_CAPTURE" &
exit_underlay_capture_pid=$!

sleep 0.25
nestwg exec lab -- ping -c 2 -W 2 203.0.114.2 >/dev/null
nestwg status lab | grep -q $'lab\tready\t'

wait "$entry_capture_pid"
wait "$middle_capture_pid"
wait "$exit_capture_pid"
wait "$exit_underlay_capture_pid"

if tcpdump -qnnr "$ENTRY_CAPTURE" 'host 203.0.114.2' 2>/dev/null | grep -q .; then
    fail "entry observed the final destination"
fi
if ! tcpdump -qnnr "$ENTRY_CAPTURE" 'host 198.51.100.2' 2>/dev/null | grep -q .; then
    fail "entry did not observe the expected opaque flow to the exit"
fi
if tcpdump -qnnr "$MIDDLE_CAPTURE" 'host 203.0.114.2' 2>/dev/null | grep -q .; then
    fail "middle relay observed the final destination"
fi
if ! tcpdump -qnnr "$MIDDLE_CAPTURE" 'host 2001:db8:2::2' 2>/dev/null | grep -q .; then
    fail "middle relay did not observe the expected opaque flow to the exit"
fi
if ! tcpdump -qnnr "$EXIT_CAPTURE" 'host 203.0.114.2' 2>/dev/null | grep -q .; then
    fail "exit did not observe the final destination"
fi
if tcpdump -qnnr "$EXIT_UNDERLAY_CAPTURE" 'host 192.0.2.2' 2>/dev/null | grep -q .; then
    fail "exit observed the client's physical underlay address"
fi

echo "three-hop mixed-family WireGuard nesting lab passed"
echo "entry saw only the opaque inner tunnel endpoint: 198.51.100.2"
echo "middle saw only the opaque IPv6 innermost endpoint: 2001:db8:2::2"
echo "exit saw the final destination but not the client underlay: 203.0.114.2"

# A persistent chain can expose selected CIDRs to ordinary host processes.
# NestWG installs an unreachable alternative for every live route, so loss of
# the attachment cannot make protected traffic fall back to the host default.
nsenter --net="/run/netns/$C0" nestwg attach lab \
    --route 203.0.114.2/32 --route fd00:3::1/128
attachment_device="$(nsenter --net="/run/netns/$C0" nestwg status lab | awk '/host device/{sub(":", "", $3); print $3}')"
if [[ -z "$attachment_device" ]]; then
    fail "status did not report the host attachment device"
fi
if ! ip -n "$C0" -details link show "$attachment_device" | grep -q 'wireguard'; then
    fail "host attachment is not the innermost WireGuard device"
fi
nsenter --net="/run/netns/$C0" nestwg diagnose lab
if [[ "$(ip -n "$C0" route show exact 203.0.114.2/32 | wc -l)" -ne 2 ]]; then
    fail "protected CIDR does not have both active and fail-closed routes"
fi
if [[ "$(ip -n "$C0" -6 route show exact fd00:3::1/128 | wc -l)" -ne 2 ]]; then
    fail "protected IPv6 CIDR does not have both active and fail-closed routes"
fi
if ! ip netns exec "$C0" ping -c 1 -W 2 203.0.114.2; then
    ip -n "$C0" address show dev "$attachment_device" >&2
    ip -n "$C0" route show >&2
    fail "host traffic did not cross the attached WireGuard device"
fi
ip netns exec "$C0" ping -6 -c 1 -W 2 fd00:3::1 >/dev/null
ip netns exec "$C0" ping -c 1 -W 2 192.0.2.1 >/dev/null
if nestwg down lab 2>/dev/null; then
    fail "down unexpectedly removed a VPN with protected host routes"
fi
if nsenter --net="/run/netns/$C0" nestwg exec lab -- true 2>/dev/null; then
    fail "exec unexpectedly entered an attached VPN without its exit device"
fi

# Simulate sudden attachment loss by moving the WireGuard device away from the
# host. Its active route disappears, but the unreachable alternative must
# remain and win over the normal default. Detach then restores its original
# payload location and name.
ip -n "$C0" link set "$attachment_device" netns "$PAYLOAD"
if ip netns exec "$C0" ip route get 203.0.114.2 >/dev/null 2>&1; then
    fail "protected traffic fell back after attachment device loss"
fi
if ip netns exec "$C0" ip -6 route get fd00:3::1 >/dev/null 2>&1; then
    fail "protected IPv6 traffic fell back after attachment device loss"
fi
if ! ip -n "$C0" route show exact 203.0.114.2/32 type unreachable | grep -q '^unreachable'; then
    fail "fail-closed route disappeared with the attachment device"
fi
if ! ip -n "$C0" -6 route show exact fd00:3::1/128 type unreachable | grep -q '^unreachable'; then
    fail "IPv6 fail-closed route disappeared with the attachment device"
fi
nsenter --net="/run/netns/$C0" nestwg detach lab
if ip -n "$C0" route show exact 203.0.114.2/32 | grep -q .; then
    fail "detach left host routes behind"
fi
if ip -n "$C0" -6 route show exact fd00:3::1/128 | grep -q .; then
    fail "detach left IPv6 host routes behind"
fi
ip -n "$PAYLOAD" link show nwg2 >/dev/null

# Teardown failures must retain enough state for a safe retry. Exercise a
# failure before namespace deletion, after namespace deletion, and after the
# resolver is gone but before the final state record is removed.
if NESTWG_FAILPOINT=down-delete-namespace nestwg down lab 2>/dev/null; then
    fail "namespace-deletion failpoint unexpectedly succeeded"
fi
assert_lab_namespaces_present
if [[ ! -e /run/nestwg/lab.json || ! -e /run/nestwg/lab.resolv.conf ]]; then
    fail "namespace-deletion failure discarded recovery state"
fi

if NESTWG_FAILPOINT=down-delete-resolver nestwg down lab 2>/dev/null; then
    fail "resolver-deletion failpoint unexpectedly succeeded"
fi
if ip netns list | grep -Eq '^nwg-lab-(t[0-9]+|app)([[:space:]]|$)'; then
    fail "resolver-deletion failure left namespaces behind"
fi
if [[ ! -e /run/nestwg/lab.json || ! -e /run/nestwg/lab.resolv.conf ]]; then
    fail "resolver-deletion failure discarded retry state"
fi
nestwg down lab
assert_lab_absent

nsenter --net="/run/netns/$C0" nestwg up "$KEY_DIR/chain.yaml"
if NESTWG_FAILPOINT=down-delete-state nestwg down lab 2>/dev/null; then
    fail "state-deletion failpoint unexpectedly succeeded"
fi
if ip netns list | grep -Eq '^nwg-lab-(t[0-9]+|app)([[:space:]]|$)'; then
    fail "state-deletion failure left namespaces behind"
fi
if [[ ! -e /run/nestwg/lab.json || -e /run/nestwg/lab.resolv.conf ]]; then
    fail "state-deletion failure did not preserve exactly the retry record"
fi
nestwg down lab
assert_lab_absent
