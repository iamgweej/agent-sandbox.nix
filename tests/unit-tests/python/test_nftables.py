from launcher.lib.build_spec import PortRange
from launcher.lib.launch_config.linux.nftables import get_nft_rules

GATEWAY_IP = "10.0.2.2"
PROXY_PORT = 12345
FORWARDER_PORT = 8118
ALLOWED_HOST_PORTS = [PortRange(first=5432, last=5432)]


def _reply_accepts(rules: list[str]) -> list[str]:
    return [rule for rule in rules if "ct state established" in rule]


def test_every_published_port_gets_its_own_reply_accept() -> None:
    rules = get_nft_rules(GATEWAY_IP, PROXY_PORT, ALLOWED_HOST_PORTS, [18944, 18945])

    assert _reply_accepts(rules) == [
        "add rule ip sandbox_filter output tcp sport 18944 ct state established accept",
        "add rule ip sandbox_filter output tcp sport 18945 ct state established accept",
    ]


def test_no_reply_accepts_without_published_ports() -> None:
    rules = get_nft_rules(GATEWAY_IP, PROXY_PORT, ALLOWED_HOST_PORTS)

    assert _reply_accepts(rules) == []


def test_open_mode_emits_no_reply_accepts() -> None:
    # Open mode's output policy is accept, so replies need no rule of their own.
    rules = get_nft_rules(GATEWAY_IP, None, ALLOWED_HOST_PORTS, [18944])

    assert _reply_accepts(rules) == []


def test_a_port_range_is_one_nft_range() -> None:
    rules = get_nft_rules(GATEWAY_IP, PROXY_PORT, [PortRange(first=3000, last=3999)])

    assert (
        f"add rule ip sandbox_filter output ip daddr {GATEWAY_IP} "
        "tcp dport 3000-3999 accept"
    ) in rules


def test_forwarder_port_is_exempt_from_dnat_before_any_dnat() -> None:
    # Privoxy is on the namespace's own loopback; localhost:* would otherwise
    # send its port to the host.
    rules = get_nft_rules(GATEWAY_IP, PROXY_PORT, None, (), FORWARDER_PORT)

    exempt = (
        "add rule ip sandbox_nat output ip daddr 127.0.0.1 "
        f"tcp dport {FORWARDER_PORT} accept"
    )
    first_dnat = next(i for i, rule in enumerate(rules) if "dnat to" in rule)
    assert rules.index(exempt) < first_dnat
