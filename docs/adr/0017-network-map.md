# 0017 The network map: who reaches this Mac, and the way out

**Context.** The Network tab listed where this Mac connects, but not who tries to reach it. The collector dropped
incoming connection attempts, so a scan of closed ports left no trace, and nothing watched the devices on the local
network or the router. The user asked for a map of routes out and of the neighbourhood.

**Decision.** The collector gathers four facts, passively: incoming connection attempts (a SYN marked "in" in packet
capture, counted per address and port), TCP listeners with how widely they listen (libproc), the neighbour tables
(`arp -an`, `ndp -an`, one device per hardware address, named by reverse DNS) and the routes (`netstat -rn`: the
default gateway that isn't tied to one interface, and routes through VPN interfaces). It sends them as one
`{"kind":"netmap",…}` line every 10 s (neighbours and routes every 30 s) to clients that want `net`. Nothing is sent
to find any of it: no scans, no traceroute, no lookups beyond the reverse DNS the collector already does.

The app keeps devices and tries sealed in `network-map.json` (tries by the hour for 7 days, devices for 30, yours
always). The first report is the network as it was: those devices are never new. `NetworkMapBuilder` draws four
columns (reaching this Mac, this Mac, the way out, destinations) from those facts and the firewall's outgoing
connections, folds each column to its first few with "and N more", and keeps blocked and new destinations in view.

Three things raise a story, all rare: ten ports tried from one address on your network within a minute (*Port scan*),
a device first seen today reaching a listening program (*New device reached this Mac*), and the router's hardware
address changing (*Router changed*). Tries from the internet are shown, not raised: scanners reach every public
address all day. A program listening on all networks is shown in orange with advice, not raised: developers start
servers all the time.

**Update: every connection out, and what devices are.** The first version took outgoing connections from the
firewall's list, which keeps only what the firewall wouldn't simply allow (and nothing while it is off), so ordinary
connections and everything to the local network were missing. The store now records every outgoing connection itself
(`observeOutgoing`, by program and destination, counted by the hour), and a connection to a device on your network ends
at that device. Devices are named by their maker (the first three bytes of the hardware address in IEEE's public
registry, `assets/oui.tsv` from `scripts/make-oui.py`, shipped and never fetched) and by what they announce over Bonjour
(AirPlay, companion link, device info, Cast, printers, HomeKit TXT records: model and name). Bonjour browsing sends
multicast questions on the local network, once every 15 minutes for a minute. That is a small step from "only
listens": the questions never leave the network, macOS asks the user first, and they are the ones the Finder sends.

**Update: networks, any range, blocking.** "Your network" is the subnets this Mac is on now (from its own addresses
and netmasks), not the private ranges, so an office on 10.20.0.0/16 or a public range counts, and a private address
elsewhere doesn't. A network is known by its router's hardware address: devices, tries and connections to devices
remember the network they were on, the map shows the current one, and a network's first report is its baseline.
*Router changed* needs the same network: at least two of the other devices, and half of them, known on the old
router. Otherwise it is a move (home to work, both on 192.168.1.1). Blocking from the map: devices and addresses
both ways and ports incoming are pf rules in their own anchor (`AddressBlock`), held whatever the firewall's mode and
removed by the same watchdog when the collector ends. A device is blocked by its addresses on the current network
(they follow it when they change), and the router never. A program's block marks its connections' patterns, a
domain's adds a blocked destination (0015): the firewall's, so Ask and Strict. Each way out keeps its two busiest
destinations in view, and a section can be shown whole.

**Consequences.** A device that never answers ARP or neighbour discovery, and traffic on the network that doesn't
involve this Mac, stay invisible. "Refused" means nothing listened on that port, so a try the system firewall dropped
at a listening port counts as reached.
Location and owner lookups for addresses would send them off the Mac and are left out.
