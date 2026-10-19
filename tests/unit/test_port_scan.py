"""Unit tests for detection/rules/port_scan.py (INDS-45)."""

from detection.rules.port_scan import detect_port_scans

ATTACKER = "192.168.50.66"
CAMERA = "192.168.50.20"
LAPTOP = "192.168.50.11"


def attempts(src, dst, ports, start=0, step=1):
    """Build one connection attempt per port, `step` seconds apart."""
    return [
        {"time": start + i * step, "src": src, "dst": dst, "port": port}
        for i, port in enumerate(ports)
    ]


def test_twenty_ports_in_a_few_seconds_is_a_port_scan():
    events = attempts(ATTACKER, CAMERA, range(1, 21))
    result = detect_port_scans(events)
    assert result == [
        {
            "type": "port_scan",
            "source": ATTACKER,
            "target": CAMERA,
            "distinct_ports": 20,
            "first_seen": 0,
            "last_seen": 19,
        }
    ]


def test_nineteen_ports_is_not_enough():
    events = attempts(ATTACKER, CAMERA, range(1, 20))
    assert detect_port_scans(events) == []


def test_ports_spread_over_more_than_60_seconds_are_not_flagged():
    # 20 ports, one every 5 seconds: never 20 inside the same 60 s window
    events = attempts(ATTACKER, CAMERA, range(1, 21), step=5)
    assert detect_port_scans(events) == []


def test_same_port_many_times_is_normal_traffic():
    events = attempts(LAPTOP, CAMERA, [443] * 50)
    assert detect_port_scans(events) == []


def test_only_the_scanning_device_is_flagged():
    events = attempts(ATTACKER, CAMERA, range(1, 21)) + attempts(LAPTOP, CAMERA, [80, 443])
    result = detect_port_scans(events)
    assert len(result) == 1
    assert result[0]["source"] == ATTACKER


def test_ports_are_counted_per_target():
    # 10 ports on each of two targets: not 20 on the same target
    events = attempts(ATTACKER, CAMERA, range(1, 11)) + attempts(ATTACKER, LAPTOP, range(1, 11))
    assert detect_port_scans(events) == []


def test_events_out_of_order_are_still_detected():
    events = list(reversed(attempts(ATTACKER, CAMERA, range(1, 21))))
    assert len(detect_port_scans(events)) == 1


def test_no_events():
    assert detect_port_scans([]) == []


def test_custom_threshold():
    events = attempts(ATTACKER, CAMERA, [22, 80, 443])
    assert len(detect_port_scans(events, port_threshold=3)) == 1