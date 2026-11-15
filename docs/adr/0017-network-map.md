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

**Consequences.** A device that never answers ARP or neighbour discovery, and traffic on the network that doesn't
involve this Mac, stay invisible. "Refused" means nothing listened on that port, so a try the system firewall dropped
at a listening port counts as reached. Blocking a device is not part of this: it needs its own design in Protection.
Location and owner lookups for addresses would send them off the Mac and are left out.
