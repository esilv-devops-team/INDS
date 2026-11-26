import json
import subprocess
from unittest.mock import Mock

import pytest

from gateway import firewall


def test_policy_scopes_both_directions_and_starts_with_no_blocks():
    lines = firewall.render_policy("br-inds", "lan0", "wan0").splitlines()
    assert lines[0] == "create table bridge inds_gateway"
    assert lines[1] == "add set bridge inds_gateway blocked_macs { type ether_addr; }"
    assert "hook forward priority 0; policy accept;" in lines[2]
    assert 'iifname "lan0" oifname "wan0" ether saddr @blocked_macs' in lines[3]
    assert 'iifname "wan0" oifname "lan0" ether daddr @blocked_macs' in lines[4]
    assert all('meta ibrname "br-inds" meta obrname "br-inds"' in rule for rule in lines[3:])


@pytest.mark.parametrize("guest_port", ["lan*", 'lan"; flush ruleset', "../lan", "br-inds", "a" * 16])
def test_policy_rejects_unsafe_or_duplicate_interfaces(guest_port):
    with pytest.raises(ValueError):
        firewall.render_policy("br-inds", guest_port, "wan0")


def test_bridge_check_requires_both_members(tmp_path, monkeypatch):
    bridge = tmp_path / "br-inds"
    (bridge / "bridge").mkdir(parents=True)
    masters = {tmp_path / "lan0/master": bridge}
    resolve = type(bridge).resolve

    def resolve_master(path, *, strict=False):
        if path in masters:
            return masters[path]
        return resolve(path, strict=strict)

    monkeypatch.setattr(type(bridge), "resolve", resolve_master)
    with pytest.raises(ValueError, match="wan0 is not a member"):
        firewall.verify_bridge("br-inds", ["lan0", "wan0"], root=tmp_path)
    masters[tmp_path / "wan0/master"] = bridge
    firewall.verify_bridge("br-inds", ["lan0", "wan0"], root=tmp_path)


@pytest.mark.parametrize(("check", "options"), [(True, ["--check"]), (False, [])])
def test_policy_passes_one_transaction_to_nft(monkeypatch, check, options):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(firewall.subprocess, "run", run)
    firewall.run_policy("create table bridge inds_gateway\n", check=check)
    assert run.call_args.args[0] == ["nft", *options, "--file", "-"]
    assert run.call_args.kwargs["input"] == "create table bridge inds_gateway\n"


def test_existing_policy_is_preserved_on_install_failure(monkeypatch):
    run = Mock(return_value=subprocess.CompletedProcess([], 1, "", "File exists"))
    monkeypatch.setattr(firewall.subprocess, "run", run)
    with pytest.raises(ValueError, match="File exists"):
        firewall.run_policy(firewall.render_policy("br-inds", "lan0", "wan0"), check=False)
    run.assert_called_once()


def test_block_readback_is_required(monkeypatch):
    mac = "02:00:00:00:00:01"
    members = Mock(side_effect=[set(), {mac}, {mac}, {mac}])
    apply = Mock()
    monkeypatch.setattr(firewall, "blocked_macs", members)
    monkeypatch.setattr(firewall, "run_policy", apply)
    firewall.set_block(mac, True)
    with pytest.raises(ValueError, match="did not confirm"):
        firewall.set_block(mac, False)
    assert [call.args[0].split()[0] for call in apply.call_args_list] == ["add", "delete"]


def test_json_reader_uses_the_dedicated_set(monkeypatch):
    definition = {"set": {"name": firewall.BLOCK_SET, "type": "ether_addr", "elem": ["02:00:00:00:AB:01"]}}
    output = json.dumps({"nftables": [{"metainfo": {}}, definition]})
    read = Mock(return_value=subprocess.CompletedProcess([], 0, output))
    monkeypatch.setattr(firewall.subprocess, "run", read)
    assert firewall.blocked_macs() == {"02:00:00:00:ab:01"}
    assert read.call_args.args[0][-3:] == ["bridge", firewall.TABLE, firewall.BLOCK_SET]


def test_routed_policy_and_timed_element_use_only_owned_forwarding_set(monkeypatch):
    policy = firewall.render_routed_policy("eth1", "eth0")
    assert 'iifname "eth1" oifname "eth0" ether saddr @blocked_macs' in policy
    assert "hook forward" in policy and "flags timeout" in policy
    mac = "02:00:00:00:00:42"
    definition = {"set": {"name": firewall.BLOCK_SET, "type": "ether_addr",
                          "elem": [{"elem": {"val": mac, "timeout": 60}}]}}
    empty = {"set": {"name": firewall.BLOCK_SET, "type": "ether_addr"}}
    outputs = [json.dumps({"nftables": [item]}) for item in (empty, definition)]
    run = Mock(side_effect=[subprocess.CompletedProcess([], 0, output) for output in outputs])
    applied = Mock()
    monkeypatch.setattr(firewall.subprocess, "run", run)
    monkeypatch.setattr(firewall, "run_policy", applied)
    firewall.set_block(mac, True, routed=True, timeout_seconds=60)
    applied.assert_called_once_with(
        f"add element inet {firewall.ROUTED_TABLE} {firewall.BLOCK_SET} {{ {mac} timeout 60s }}\n", check=False,
    )
