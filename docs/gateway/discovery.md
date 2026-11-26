# Device discovery (INDS-39)

## Routed Raspberry Pi

Managed monitoring uses `INDS_MONITOR_INTERFACE=eth1` for the Pi's LAN.
The routed default is `192.168.50.1/24`, overridable with
`INDS_LAN_ADDRESS`. The collector reads
`/var/lib/misc/dnsmasq.leases` (override with `INDS_DHCP_LEASE_FILE`)
and reachable IPv4 entries from `ip neigh`. Set `INDS_MONITOR_AP_MAC`
if the access point itself needs to be excluded from inventory.

Confirmed leases take precedence over reachable neighbors and packet ARP claims.
A DHCP request can identify a MAC and hostname without establishing ownership
of the requested IP. Leases alone do not establish recent activity. A private
MAC is treated as a separate observed identity. Capture on `eth1` sees routed
client traffic and frames delivered by the AP to that interface. Traffic switched
locally by the AP may not reach it. No second capture interface is required
for this configuration.

## Standalone and legacy bridge discovery

`gateway/discovery.py` runs on the Pi. It listens to ARP and DHCP on the port
connected to the AP, and every 30 seconds sends the devices it saw to
`POST /api/devices/observations`. The backend saves them (INDS-41).

Running the script = monitoring ON. Ctrl+C = OFF. The saved devices stay in
the database.

## Run

Needs `tcpdump` installed and `sudo` (raw sockets).

```sh
python -m uvicorn backend.main:app --host 127.0.0.1
sudo .venv/bin/python -m gateway.discovery --iface <AP_PORT> --bridge-port --ignore <AP_MAC>
```

| Option | Meaning |
| --- | --- |
| `--iface` | Interface to listen on (on the Pi: the port connected to the AP) |
| `--bridge-port` | Only keep devices the bridge learned on that port (Pi only) |
| `--ignore` | MACs to skip, for example the AP itself |
| `--interval` | Seconds between sends (default 30) |
| `--api` | Backend URL |

The POST endpoint has no login yet, so the backend must stay on 127.0.0.1.

## Visibility limitations

- Traffic between two clients of the same AP never reaches the Pi. Devices
  are still discovered because they all talk to the router (DHCP, ARP).
- Phones use random MAC addresses per network. A phone can show up as a new
  device if it changes its MAC. Vendor is then `Randomized`.
- Hostname is only known if the device sends it in DHCP. Many Android phones don't.
- The vendor list is small, so most devices show `Unknown`.
- Last seen is only updated when a device sends ARP or DHCP (every few
  minutes), plus up to 30 s before the batch is sent.
- Devices that only use IPv6 are not discovered.
- Without `--bridge-port` (for example on a laptop), the router and other
  devices on the router side are listed too.
