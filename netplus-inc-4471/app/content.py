TITLE = 'Network+ Troubleshooting Lab: INC-4471'

BRIEFING = (
    'Ticket INC-4471: the Finance workstation FIN-WS07 cannot open the intranet portal '
    'at http://portal.corp.local. You are the on-site network technician. Log in to the '
    'workstation, work the problem bottom-up through the OSI model, fix each fault you find '
    'and collect the four flags on the way. Flags look like NPLUS{...}.'
)

STAGES = [
    {
        'id': '1', 'points': 100,
        'title': 'Know your network',
        'tag': 'Layers 2-3: IP config, ARP, host discovery',
        'desc': ('Check the workstation\'s own settings first: interface, IP address, subnet mask, '
                 'default gateway and DNS server. Can it reach its gateway? Then find the other '
                 'devices on the LAN. One of them is configured correctly, so you can compare '
                 'against it. Its flag is waiting for you.'),
        'hints': [
            'Start with: ip addr, ip route, cat /etc/resolv.conf. Then ping the default gateway.',
            'ip neigh shows whether ARP for the gateway worked (FAILED or INCOMPLETE means nobody answered). '
            'Find the live hosts with: sudo arp-scan -l   or   sudo nmap -sn 10.10.10.0/24',
            'Look at the vendor names in the scan. Printers usually have a built-in web page: '
            'curl http://<printer-ip>/',
        ],
    },
    {
        'id': '2', 'points': 200,
        'title': 'Fix the IP configuration',
        'tag': 'Layer 3 and DNS: default gateway, resolver',
        'desc': ('Use the known-good settings to correct the workstation\'s default gateway and DNS server. '
                 'Once name resolution works, ask the DNS server about the portal. It publishes more '
                 'than just an IP address.'),
        'hints': [
            'Replace the default route: sudo ip route replace default via <correct-gateway>',
            'Point the resolver at the right server: '
            'printf "search corp.local\\nnameserver <dns-ip>\\n" | sudo tee /etc/resolv.conf',
            'Try other record types: dig portal.corp.local TXT   or   nslookup -type=TXT portal.corp.local',
        ],
    },
    {
        'id': '3', 'points': 300,
        'title': 'Something is in the path',
        'tag': 'Layer 4, insecure protocols, packet capture',
        'desc': ('Ping and DNS now work, yet the portal page never loads. Work out where the traffic dies '
                 'and get a session on the device responsible. You do not have its password, but the '
                 'network admin\'s PC logs in to that device every half minute using an old cleartext '
                 'protocol, and your switch port behaves like a mirror (SPAN) port.'),
        'hints': [
            'Compare ping with curl -m 5 http://portal.corp.local. Then: sudo nmap -Pn -p 80 portal.corp.local. '
            'What is the difference between "closed" and "filtered"?',
            'Only one device sits between you and the server network. Scan it: sudo nmap 10.10.10.1. '
            'Which management protocol is open?',
            'Capture the admin\'s login: sudo tcpdump -i eth0 -n -A port 23   (wait up to 30 seconds), '
            'then: telnet 10.10.10.1',
        ],
    },
    {
        'id': '4', 'points': 400,
        'title': 'Fix the root cause',
        'tag': 'ACLs, change control, verification',
        'desc': ('Find the configuration that blocks the portal and fix it without opening up anything '
                 'else. Then load the portal from the workstation to prove the ticket is resolved.'),
        'hints': [
            'On the router: show access-lists. Run curl again and watch which line\'s match counter goes up.',
            'show logging and show running-config tell you who changed what, and why.',
            'configure terminal, then ip access-list extended LAN-IN, then no <sequence-number>, then end. '
            'Verify with: curl http://portal.corp.local',
        ],
    },
]

MAX_SCORE = sum(s['points'] for s in STAGES)
