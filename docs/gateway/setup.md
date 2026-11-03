# Inline gateway setup (INDS-36)

Status: preparation only; not yet validated on the Pi. Apply on a development
network with local console access. This procedure changes the Pi's networking.

## Topology and equipment

```text
Customer -> Guest Wi-Fi AP -> Pi Ethernet bridge -> Router -> Internet
                              two wired ports
```

Use a Raspberry Pi 4, suitable power supply, Raspberry Pi OS with NetworkManager,
a USB 3.0 Gigabit Ethernet adapter, a separate AP operating in bridge/AP mode,
and two Ethernet cables. Confirm the adapter is supported by the installed OS.
Use the AP's documented LAN/uplink port for AP mode, not an active NAT router mode.

For this first milestone, use one untagged guest network. Tagged VLAN trunks,
multiple networks, and AP/router combinations without a separate wired AP path
need separate validation. Do not create a second AP-to-router cable: it would
bypass INDS and could form a network loop.

The Pi uses a transparent Layer 2 bridge. The existing router supplies client
DHCP, DNS configuration, and the default gateway. Do not enable a Pi DHCP server
or NAT. The bridge requests its own management address through DHCP; reserve that
address on the router after setup. DHCP availability is not a forwarding dependency.

## Inspect before changing anything

1. Provision the OS and enable administrator access. Use a keyboard/display or
   another independently verified management path during changes. Ethernet SSH
   can disconnect when its interface joins the bridge.
2. Connect the USB adapter. Identify both interfaces from actual output, physical
   labels/MAC addresses, and link changes when unplugging a cable. Do not assume
   `eth0`/`eth1`; record which faces the router and which faces the AP.
3. Run the read-only helper from the repository root:

   ```sh
   sh gateway/scripts/inspect-network.sh
   sudo nft list ruleset
   ```

4. Record OS/NetworkManager versions, interface MACs/names, current management
   address, active connection UUIDs, and their autoconnect settings. Keep these
   details in `gateway/local/`. Back up the NetworkManager connection profiles to
   a private location on the Pi; they can contain secrets and must not enter Git.
5. Check for existing bridge/netfilter/firewall policies that could filter or
   queue bridged traffic. Do not flush the firewall or override host policy.
   Resolve conflicts before continuing. No application-controlled packet queue
   belongs in the forwarding path.
6. Record the direct AP-to-router performance baseline using the verification
   guide before inserting the Pi.

## Prepare and activate

Read [the command template](../../gateway/config/bridge.nmcli.example), then copy
it into ignored `gateway/local/` and replace the interface placeholders. Execute
reviewed commands individually on the Pi; the template is not a shell script.

The commands use modern NetworkManager `controller`/`port-type` terminology.
Check local `nmcli` help/version first; older versions may expose the equivalent
`master`/`slave-type` names. Do not mix NetworkManager with another network manager.

1. Confirm `br-inds` and the three `inds-*` profile names are unused.
2. Create the inactive bridge and two port profiles from the template.
3. Record and disable autoconnect on existing Ethernet profiles for these two
   ports using `sudo nmcli connection modify uuid <UUID> connection.autoconnect no`.
   Preserve the profiles and original values for recovery. Never disable an
   unrelated management profile.
4. With local console access, activate the bridge and both port profiles.
   Activation replaces the previous connections on those ports.
5. Wire router -> router-facing Pi port and AP -> AP-facing Pi port. Ensure the
   AP has no alternative uplink. Allow STP convergence before testing.
6. Check bridge membership and management addressing, then run the client checks
   in [verification](verification.md). An internet test from the Pi alone does
   not prove forwarding between ports.
7. Only after these checks succeed, enable autoconnect on all three profiles using
   the template. Reboot and repeat the checks before declaring setup complete.

IPv6 client traffic must also work when the upstream network provides it. Do not
silently limit later monitoring/enforcement to IPv4. No firewall rules or INDS
service are needed for this forwarding-only milestone.

## Recovery

If connectivity fails, use the local console. First physically restore the
original AP-to-router cable path and disconnect the Pi from that path. This is
manual recovery, not automatic hardware failover.

Disable autoconnect on the three new profiles, then bring down the two port
profiles followed by the bridge, using `sudo nmcli connection down <PROFILE>`.
Restore each previous Ethernet profile's recorded autoconnect value and activate
the appropriate original router-facing connection by UUID. Verify management
access. Leave the inactive INDS profiles for inspection; delete them only after
confirming they are the profiles created by this procedure.

## References

- [Raspberry Pi networking configuration](https://www.raspberrypi.com/documentation/computers/configuration.html)
- [NetworkManager nmcli reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html)
- [NetworkManager connection settings](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html)
