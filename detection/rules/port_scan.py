"""Port scan detection rule (INDS-45).

A device that tries many different ports on the same target in a short
time is probably scanning it (reconnaissance before an attack).
Default thresholds from the SRS: 20 distinct ports within 60 seconds.
"""

PORT_THRESHOLD = 20
WINDOW_SECONDS = 60


def detect_port_scans(events, port_threshold=PORT_THRESHOLD, window_seconds=WINDOW_SECONDS):
    """Return one detection event per (source, target) pair that scans.

    events: list of dicts {"time": seconds, "src": ip, "dst": ip, "port": int}
    """
    # 1. Group the connection attempts by (source, target)
    by_pair = {}
    for event in events:
        key = (event["src"], event["dst"])
        by_pair.setdefault(key, []).append(event)

    detections = []
    for (src, dst), pair_events in by_pair.items():
        pair_events.sort(key=lambda e: e["time"])

        # 2. Slide a time window over the attempts, oldest first
        start = 0
        for end in range(len(pair_events)):
            while pair_events[end]["time"] - pair_events[start]["time"] > window_seconds:
                start += 1

            ports = {e["port"] for e in pair_events[start:end + 1]}

            # 3. Too many different ports in the window -> port scan
            if len(ports) >= port_threshold:
                detections.append({
                    "type": "port_scan",
                    "source": src,
                    "target": dst,
                    "distinct_ports": len(ports),
                    "first_seen": pair_events[start]["time"],
                    "last_seen": pair_events[end]["time"],
                })
                break

    return detections