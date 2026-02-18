SERVICES = [
    {"name": "website",   "icon": "bi-globe2",               "desc": "personal site", "url": "https://flysqu.pink",           "tag": "public"},
    {"name": "nextcloud", "icon": "bi-cloud-fill",           "desc": "files & sync",  "url": "https://cloud.flysqu.pink",     "tag": "public"},
    {"name": "jellyfin",  "icon": "bi-collection-play-fill", "desc": "media server",  "url": "https://media.flysqu.pink",     "tag": "public"},
    {"name": "bitwarden", "icon": "bi-shield-lock-fill",     "desc": "passwords",     "url": "https://bitwarden.flysqu.pink", "tag": "public"},
    # VPN-only services: check_url uses the internal LAN IP for health checks
    # while url is what you'd open in your browser when connected to the VPN.
    {"name": "proxmox",   "icon": "bi-server",               "desc": "hypervisor",    "url": "https://10.8.0.2:8006",         "tag": "vpn",
     "check_url": "https://192.168.1.1:8006"},
]
