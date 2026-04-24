This repo contains a discovery of local devices on the LAN network.

Features:
1. Automatically detects the local network (192.x.x.x), excluding VPNs and virtual adapters.
2. Finds all connected devices.
3. For each device it will try to determine what device it is and try to fetch as many details as possible, WITHOUT trying to use exploits or CVEs.
4. allow the user to manually rename or annotate each found device.
5. works both as CLI and provide Web interface / app.