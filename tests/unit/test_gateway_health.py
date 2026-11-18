from collections import namedtuple

from backend.services import gateway_health

Stat = namedtuple("Stat", "isup speed")
Counter = namedtuple("Counter", "bytes_recv bytes_sent")
Sensor = namedtuple("Sensor", "current")


def fake_network(monkeypatch, counters, clock):
    stats = {"lo": Stat(True, 0), "eth0": Stat(True, 1000), "eth1": Stat(False, 0), "br-inds": Stat(True, 0), "utun3": Stat(True, 0)}
    monkeypatch.setattr(gateway_health.psutil, "net_if_stats", lambda: stats)
    monkeypatch.setattr(gateway_health.psutil, "net_io_counters", lambda pernic: counters)
    monkeypatch.setattr(gateway_health.time, "monotonic", lambda: clock[0])


def test_interfaces_and_throughput(monkeypatch):
    gateway_health.last_counters.clear()
    clock = [100.0]
    counters = {
        "lo": Counter(5, 5),
        "eth0": Counter(1000, 500),
        "eth1": Counter(0, 0),
        "br-inds": Counter(2000, 1000),
        "utun3": Counter(1, 1),
    }
    fake_network(monkeypatch, counters, clock)

    interfaces = gateway_health.read_interfaces()
    assert [item["name"] for item in interfaces] == ["br-inds", "eth0", "eth1"]
    assert interfaces[0]["is_bridge"] is True
    assert interfaces[0]["rx_rate"] is None
    assert interfaces[1]["speed_mbps"] == 1000
    assert interfaces[2]["speed_mbps"] is None

    clock[0] = 102.0
    counters["br-inds"] = Counter(6000, 3000)
    interfaces = gateway_health.read_interfaces()
    assert interfaces[0]["rx_rate"] == 2000
    assert interfaces[0]["tx_rate"] == 1000


def test_temperature(monkeypatch):
    monkeypatch.setattr(gateway_health.psutil, "sensors_temperatures", lambda: {"empty": [], "cpu_thermal": [Sensor(48.234)]}, raising=False)
    assert gateway_health.read_temperature() == 48.2

    monkeypatch.setattr(gateway_health.psutil, "sensors_temperatures", lambda: {}, raising=False)
    assert gateway_health.read_temperature() is None

    monkeypatch.delattr(gateway_health.psutil, "sensors_temperatures", raising=False)
    assert gateway_health.read_temperature() is None


def test_system_values():
    system = gateway_health.read_system()
    assert system["cpu_count"] >= 1
    assert 0 <= system["memory"]["percent"] <= 100
    assert system["memory"]["used"] <= system["memory"]["total"]
    assert system["uptime_seconds"] > 0
    assert len(system["load_average"]) == 3


def test_database_down():
    class BrokenSession:
        def execute(self, _query):
            raise RuntimeError("database is locked")

    services = gateway_health.check_services(BrokenSession(), [])
    assert services == [{"name": "Database", "state": "down", "detail": "SQLite does not answer"}]