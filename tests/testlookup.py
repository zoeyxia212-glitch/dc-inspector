import pytest

from inspector import lookup


@pytest.mark.parametrize(
    "query, expected",
    [
        ("AST-000123", "asset_id"),
        ("ast-5", "asset_id"),
        ("SH01-A03", "rack"),
        ("sh10", "rack"),
        ("10.3.2.12", "ip"),
        ("10.3.", "ip"),
    ],
)
def test_detect_query_type(query, expected):
    assert lookup.detect_query_type(query) == expected


@pytest.mark.parametrize("bad", ["hello", "AST-", "SH1-A3", "10.1.2.3.4", ""])
def test_invalid_queries_are_rejected(bad):
    with pytest.raises(lookup.InvalidQuery):
        lookup.detect_query_type(bad)


def test_exact_ip(conn):
    results = lookup.search(conn, "10.3.2.12")
    assert len(results) == 1
    assert results[0]["hostname"] == "sh03-a02-srv02"
    assert results[0]["rack"] == "SH03-A02"


def test_out_of_range_ip_is_invalid(conn):
    with pytest.raises(lookup.InvalidQuery):
        lookup.search(conn, "10.3.2.999")


def test_ip_prefix_does_not_overmatch(conn):
    # "10.1." must not return devices in 10.10.x.x
    results = lookup.search(conn, "10.1.")
    assert results and all(r["ip"].startswith("10.1.") for r in results)
    assert all(r["datacenter"] == "SH01" for r in results)


def test_rack_search_returns_switch_and_servers(conn):
    results = lookup.search(conn, "sh01-a01")
    assert len(results) == 9
    assert sum(r["device_type"] == "switch" for r in results) == 1


def test_whole_datacenter_search(conn):
    assert len(lookup.search(conn, "SH05")) == 36


def test_asset_id_without_leading_zeros(conn):
    assert lookup.search(conn, "AST-1")[0]["asset_id"] == "AST-000001"


def test_server_detail_shows_switch_peer(conn):
    detail = lookup.get_device_detail(conn, "AST-000002")  # first server in SH01-A01
    assert detail["device_type"] == "server"
    eth0 = next(p for p in detail["ports"] if p["name"] == "eth0")
    assert eth0["peer_hostname"] == "sh01-a01-tor"
    assert eth0["peer_port"] == "GE1/0/1"


def test_switch_detail_shows_server_peers(conn):
    detail = lookup.get_device_detail(conn, "AST-000001")  # ToR switch in SH01-A01
    assert len(detail["ports"]) == 48
    cabled = [p for p in detail["ports"] if p["peer_hostname"]]
    assert len(cabled) == 16


def test_unknown_device_returns_none(conn):
    assert lookup.get_device_detail(conn, "AST-999999") is None
