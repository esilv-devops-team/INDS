from io import BytesIO
from unittest.mock import Mock

import pytest

from gateway import firewall_client, firewall_helper


@pytest.mark.parametrize(("data", "expected"), [
    (b"block 02:00:00:00:00:42 30\n", b"OK\n"),
    (b"block 02:00:00:00:00:01 30\n", b"ERROR\n"),
    (b"unblock 02:00:00:00:00:42\n", b"OK\n"),
    (b"flush ruleset\n", b"ERROR\n"),
    (b"block 02:00:00:00:00:42 30; flush ruleset\n", b"ERROR\n"),
    (b"clear\n", b"OK\n"),
])
def test_helper_accepts_only_fixed_routed_operations(data, expected, monkeypatch):
    mutate, clear = Mock(), Mock()
    monkeypatch.setattr(firewall_helper.firewall, "set_block", mutate)
    monkeypatch.setattr(firewall_helper.firewall, "clear_blocks", clear)
    reply = BytesIO()
    firewall_helper.serve(BytesIO(data), reply, {"02:00:00:00:00:01"})
    assert reply.getvalue() == expected
    if expected == b"ERROR\n":
        mutate.assert_not_called()
        clear.assert_not_called()
    elif data.startswith(b"clear"):
        clear.assert_called_once_with(routed=True)
    else:
        assert mutate.call_args.kwargs["routed"]


def test_expired_timeout_cannot_become_a_permanent_request(monkeypatch):
    request = Mock()
    monkeypatch.setattr(firewall_client, "request", request)
    with pytest.raises(ValueError):
        firewall_client.set_block("02:00:00:00:00:42", True, timeout_seconds=0)
    request.assert_not_called()
