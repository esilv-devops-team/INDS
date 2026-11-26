# Routed Raspberry Pi deployment plan

Status: local implementation and mocked firewall tests. Review the commands below
before running them on the Pi. The existing NetworkManager, dnsmasq, SSH, routing,
and `inds_nat`/`inds_filter` configuration stays in place.

## 1. Read-only preflight

Connect with `ssh adam@inds-pi.local`. Check `uname -m`,
`cat /etc/os-release`, `python3 --version`, `ip -br address`,
`ip route show`, `ip -j -4 neigh show dev eth1`,
`systemctl is-active dnsmasq nftables ssh`, and
`test -r /var/lib/misc/dnsmasq.leases`. Verify the intended management
client and AP MACs before any enforcement. Host rules inspection through
`sudo nft list ruleset` is privileged and requires approval even though it is read-only.

## 2. Application and monitor-only rollout

- Build the frontend on the development machine with `npm ci` and `npm run build`.
  Stage the release and its static bundle under `/opt/inds/releases/<revision>`.
- Approval required for system changes. If preflight finds missing runtime packages,
  review the exact list before `sudo apt-get install python3-venv iproute2`.
  Review `sudo useradd --system --home-dir /var/lib/inds --shell /usr/sbin/nologin inds`
  and `sudo install -d -o inds -g inds -m 0750 /var/lib/inds` if the account or directory
  does not already exist. Keep releases and service configuration root-owned.
- From the staged release, provision a venv with `python3 -m venv .venv` and install
  `.venv/bin/python -m pip install -r backend/requirements.txt -r gateway/requirements.txt`.
  Verify compatible ARM64 dependencies before systemd activation. Run
  `.venv/bin/python -m alembic -c backend/database/alembic.ini upgrade head`
  as the service identity against the intended DB after backing up any existing database.
  Running commands as another identity and installing onto the Pi require the rollout approval.
- Set `INDS_DATABASE_URL=sqlite:////var/lib/inds/inds.sqlite3`,
  `INDS_MONITOR_INTERFACE=eth1`, and `INDS_FIREWALL_ENABLED=0`. Set the
  confirmed `INDS_MONITOR_AP_MAC`, `INDS_PROTECTED_MACS`, and lease-file override
  if needed. Generate a stable secret directly into a restricted environment file.
  Enable secure cookies when HTTPS is in use. Keep initial admin setup reachable
  only over the management path.
- Review [the systemd unit](../../deploy/inds.service) running one Uvicorn process as `inds` on
  `127.0.0.1:8000`. Grant only the verified capture capability
  (`CAP_NET_RAW` is the initial candidate) and only necessary read access to
  the lease file. Confirm `ReadWritePaths=/var/lib/inds`, graceful shutdown,
  journald retention, and [the Caddy example](../../deploy/Caddyfile.example)
  serving the built UI and proxying `/api/` over HTTPS. Before initial admin setup,
  verify the chosen bind address is reachable only by the intended management
  clients. An IP bind alone provides no client authentication. Verify the proxy
  config on the target, and arrange trust of the internal TLS CA on management
  clients before browsing.
- Approve the unit, proxy configuration, access changes, and their rollback
  before installing them. Candidate commands include
  `sudo ln -s /opt/inds/releases/REVISION /opt/inds/current` for a first installation
  and `sudo install -m 0644 deploy/inds.service /etc/systemd/system/inds.service`.
  Verify the unit with `systemd-analyze verify deploy/inds.service` on the Pi when
  the staged release and service account are in place. The service activation commands are
  `sudo systemctl daemon-reload` and `sudo systemctl enable --now inds`.
  Any proxy installation, enable/reload, service restart, or reboot requires approval.
  An administrator turns monitoring on once. The configured ON/OFF preference
  then survives service restarts. A fresh database starts OFF. Startup closes
  interrupted runs and reopens capture only if the stored preference is ON.

## 3. Verify monitoring and decide on enforcement

Check gateway health and authenticated dashboard access. Connect a test phone to
the external AP, compare its lease and neighbor observations with inventory, browse
with cellular disabled, and verify traffic counters. Exercise monitoring ON/OFF and
run controlled detector/incident checks. Traffic switched wholly by the AP may be
invisible at `eth1`. Authentication-failure, DNS-anomaly, SYN-flood and
unauthorized-access detection are outside the current supported detector set.

The routed response policy is a separate `inet inds_response` table. It drops
matching MACs only on the `eth1` to `eth0` forwarding path. Pi-local traffic
and client-to-client AP traffic are outside this policy. Temporary blocks use
nftables element timeouts and the app reconciles its audit state. Monitoring stop
or process startup clears the owned set instead of reapplying old approvals.

Separate approval is required before privileged policy validation
(`sudo .venv/bin/python -m gateway.firewall check --routed --guest-port eth1 --router-port eth0`),
installation (same command with `install`), installing the dedicated
[socket](../../deploy/inds-firewall.socket) and
[worker](../../deploy/inds-firewall@.service) under a separate `inds-firewall`
identity, granting that worker its bounded kernel capability, enabling
`INDS_FIREWALL_ENABLED=1`, restarting the service, or testing a live block.
The API process has no routed nftables fallback. The helper accepts only block,
unblock, and clear requests on the INDS-owned set. Install its code and venv
root-owned and restrict its independent AP/management exclusions file.
Name the exact enrolled target, management and AP
MACs, expected restriction, duration, and rollback before live testing. Verify a
second client and SSH, DHCP and NAT throughout.

## 4. Backup and rollback

Back up SQLite using its backup API or `.backup` before upgrades. Record the
release revision and validate integrity on a copy. Preserve permissions and test
restoring to a separate location before replacing the live DB. For service
rollback, review `sudo systemctl stop inds`, restore the prior release and matching
database backup if needed, then review `sudo systemctl start inds`. For a live
firewall rollback, reverse through the API first. With approval, emergency cleanup
can use `sudo nft flush set inet inds_response blocked_macs` or
`sudo nft delete table inet inds_response` for complete removal of the owned
policy. Verify the still-working gateway services and SSH before ending the session.

## Final monitor-only rollout checklist

Prefer loopback access through an SSH tunnel for initial acceptance. This keeps
the existing public and LAN service bindings untouched. Prepare a release archive
with source, deployment files, and built `frontend/dist`. Exclude the local DB,
secrets, and development environment. Record its SHA-256 and verify it at staging.
Confirm the Pi's architecture, existing service state, free space, access account,
and lease path using the preflight above. Check `ss -ltn` for free ports 8000 and
8443. Verify a baseline phone lease, its WAN connectivity, and a second SSH session.

The following are approval-gated commands for a **first install**. Replace
`REVISION` with the approved release ID and use the approved staged archive.
If any target path or service already exists, stop and review it as an upgrade.

```sh
scp inds-REVISION.tar.gz adam@inds-pi.local:/home/adam/
sudo apt-get install python3-venv iproute2
sudo useradd --system --home-dir /var/lib/inds --shell /usr/sbin/nologin inds
sudo install -d -o root -g root -m 0755 /opt/inds/releases/REVISION
sudo install -d -o root -g root -m 0750 /etc/inds
sudo install -d -o inds -g inds -m 0750 /var/lib/inds
sudo tar --no-same-owner --no-same-permissions -xzf /home/adam/inds-REVISION.tar.gz -C /opt/inds/releases/REVISION
sudo python3 -m venv /opt/inds/releases/REVISION/.venv
sudo /opt/inds/releases/REVISION/.venv/bin/python -m pip install -r /opt/inds/releases/REVISION/backend/requirements.txt -r /opt/inds/releases/REVISION/gateway/requirements.txt
sudo ln -s /opt/inds/releases/REVISION /opt/inds/current
sudoedit /etc/inds/inds.env
sudo chmod 0600 /etc/inds/inds.env
sudo -u inds env INDS_DATABASE_URL=sqlite:////var/lib/inds/inds.sqlite3 /opt/inds/current/.venv/bin/python -m alembic -c /opt/inds/current/backend/database/alembic.ini upgrade head
sudo -u inds test -r /var/lib/misc/dnsmasq.leases
sudo systemd-analyze verify /opt/inds/current/deploy/inds.service
sudo install -m 0644 /opt/inds/current/deploy/inds.service /etc/systemd/system/inds.service
sudo systemctl daemon-reload
sudo systemctl enable --now inds
```

Run the package and account commands only if the reviewed preflight shows they
are needed. The environment file sets the database URL above,
`INDS_MONITOR_INTERFACE=eth1`, `INDS_FIREWALL_ENABLED=0`,
`INDS_COOKIE_SECURE=1`, and a stable private `INDS_SECRET_KEY`.
Use a private editor or a secret manager for the signing key. If the service
account cannot read the lease file, request separate approval for the minimum
necessary read access or an approved read-only lease feed. Keep the firewall
socket and helper uninstalled or inactive for this rollout.

For browser validation, use the existing approved Caddy binary if present.
Review any package installation separately because it may activate a default
service. Run the loopback proxy in a dedicated operator shell under `adam`
with its own TLS state. The following Pi command requires approval to start
the proxy and write its local certificate state.

```sh
env XDG_DATA_HOME=/home/adam/.local/share/inds-preview INDS_MANAGEMENT_HOST=localhost:8443 INDS_MANAGEMENT_IP=127.0.0.1 caddy run --config /opt/inds/current/deploy/Caddyfile.example --adapter caddyfile
```

From the laptop, use `ssh -N -L 8443:127.0.0.1:8443 adam@inds-pi.local`.
Verify the certificate through the authenticated SSH connection. The public
CA can be copied with `scp adam@inds-pi.local:/home/adam/.local/share/inds-preview/caddy/pki/authorities/local/root.crt inds-preview-root.crt`.
For Windows browser testing, adding trust requires approval for
`Import-Certificate -FilePath .\inds-preview-root.crt -CertStoreLocation Cert:\CurrentUser\Root`.
Record the issued thumbprint for removal from that same store when testing is done.
Use `https://localhost:8443` and check that another LAN client
cannot reach the Pi's 8443 or 8000. Verify the API with
`curl --fail http://127.0.0.1:8000/health` from the Pi. Complete admin setup
through the tunnel, then turn monitoring on. Check actual device activity,
incident evidence, service status and audit entries. With separate approval for
`sudo systemctl restart inds`, verify that ON resumes with a fresh audit run.
Turn OFF, repeat the approved restart, and verify capture stays off. Confirm
client traffic, DHCP renewal, NAT and SSH continuity throughout. A reboot test
requires separate approval for `sudo systemctl reboot`.

If any check fails, stop the temporary proxy with Ctrl+C and close the tunnel.
With approval, remove the preview CA by its recorded exact thumbprint using
`Remove-Item -LiteralPath Cert:\CurrentUser\Root\THUMBPRINT`.
With the approved rollback, run `sudo systemctl disable --now inds` for a first
install. Preserve the release, logs, and database for diagnosis. For an upgrade,
stop the app, restore the saved release symlink and matching SQLite backup,
then restart only with approval. Confirm the phone and second SSH session still
work. The monitor-only rollback has no firewall policy to remove.
