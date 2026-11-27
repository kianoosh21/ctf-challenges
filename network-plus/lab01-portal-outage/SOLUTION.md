# Network+ Lab 01: Portal outage (INC-4471): instructor walkthrough

> **Spoiler warning.** This is the full solution. Students should not read it before the lab.

Student URL: `http(s)://<lab-host>:<port>/dashboard`. Instructor view: `/dashboard/admin`. See [README.md](README.md) for setup.

## How the lab works

- Each browser session gets a **Claim credentials** button. Clicking it gives that session a unique username and password (for example `vlan97` / `nebula-amber-71`). Credentials are tied to the browser session cookie, not the IP address, so a whole classroom behind one NAT works fine.
- A student who switches browser can use **Sign in** on the welcome page with the same credentials.
- **Launch lab** builds a private network for that student in about 10 seconds: a workstation (Docker container) plus a switch, router, printer, admin PC, DNS server and web server. Every student gets the same IP addresses, and the networks are fully isolated from each other, from the host and from the internet.
- The terminal runs in the browser. The workstation shows a `fin-ws07 login:` prompt, and the student logs in with their claimed credentials. They have sudo.
- Flags are unique per student (`NPLUS{...}`), so a flag copied from a neighbour is rejected.
- **Reset lab** rebuilds the network in its original broken state and keeps solved flags. Labs auto-stop 8 hours after launch.

## Topology (do not show students before the lab)

```
 Finance LAN 10.10.10.0/24                          Server LAN 172.16.20.0/24
 FIN-WS07  10.10.10.50 (student)  --+               +-- DNS01   172.16.20.53
 PRN-01    10.10.10.20 (HP)       --+--[SW]--RTR-01--+-- PORTAL  172.16.20.80
 ADMIN-PC  10.10.10.30 (Dell)     --+   Gi0/0 .1  Gi0/1 .1
```

Faults planted in the scenario:

1. Workstation default gateway is `10.10.10.254` (no such host). Correct: `10.10.10.1`.
2. Workstation DNS server is `10.10.10.53` (decommissioned). Correct: `172.16.20.53`.
3. Router ACL `LAN-IN` line 50 denies TCP/80 from the LAN to the portal (left behind from change CHG-2231).
4. The router is managed over telnet. The admin PC logs in every ~30 seconds with cleartext credentials, and the student's switch port sees all traffic (behaves like a SPAN/mirror port).

| Stage | Points | Concept | Where the flag is |
|---|---|---|---|
| 1. Know your network | 100 | IP config, ARP, host discovery, known-good baseline | Printer web page `http://10.10.10.20/` |
| 2. Fix the IP configuration | 200 | Default gateway, DNS resolver, DNS record types | TXT record on `portal.corp.local` |
| 3. Something is in the path | 300 | Filtered vs closed, cleartext protocols, packet capture | Router login banner |
| 4. Fix the root cause | 400 | ACLs, implicit deny, change control, verification | Portal page `http://portal.corp.local/` |

## Stage 1: Know your network (100 pts)

1. Log in at the `fin-ws07 login:` prompt with the claimed credentials. The ticket is shown on login and saved in `~/TICKET.txt`.
2. Check the workstation's own config:
   ```
   ip addr               # eth0 is UP, 10.10.10.50/24
   ip route              # default via 10.10.10.254
   cat /etc/resolv.conf  # nameserver 10.10.10.53
   ```
3. Test the gateway:
   ```
   ping -c2 10.10.10.254   # Destination Host Unreachable
   ip neigh                # 10.10.10.254 ... INCOMPLETE or FAILED
   ```
   Nothing answers ARP for the configured gateway, so nothing off-subnet can work.
4. `curl http://portal.corp.local` fails with "Could not resolve host" (DNS is also wrong).
5. Find the live hosts on the LAN:
   ```
   sudo arp-scan -l
   # 10.10.10.1   00:00:0c:..  Cisco Systems, Inc
   # 10.10.10.20  00:1b:78:..  Hewlett Packard
   # 10.10.10.30  00:14:22:..  Dell Inc.
   ```
   (`sudo nmap -sn 10.10.10.0/24` shows the same with vendor names.)
6. The HP device is a printer with a built-in web page:
   ```
   curl http://10.10.10.20/
   ```
   The page shows the printer's known-good network config (gateway `10.10.10.1`, DNS `172.16.20.53`, suffix `corp.local`) and **flag 1**.

Teaching point: hosts on the same subnet talk directly using ARP, no gateway needed. That is why the printer works while everything else fails. Comparing against a known-good device is a fast way to find a misconfiguration.

## Stage 2: Fix the IP configuration (200 pts)

1. Fix the default gateway:
   ```
   sudo ip route replace default via 10.10.10.1
   ```
2. Fix the resolver (use `tee` or `nano`; `sed -i` fails here with "Device or resource busy" because Docker bind-mounts `/etc/resolv.conf`):
   ```
   printf "search corp.local\nnameserver 172.16.20.53\n" | sudo tee /etc/resolv.conf
   ```
3. Verify:
   ```
   ping -c2 172.16.20.53
   dig portal.corp.local        # A record 172.16.20.80
   dig -x 172.16.20.80 +short   # reverse lookup: portal.corp.local.
   ```
4. Ask for other record types:
   ```
   dig portal.corp.local TXT
   nslookup -type=TXT portal.corp.local
   ```
   The TXT record holds **flag 2**.

Teaching point: the default gateway and DNS server are separate settings that fail in different ways ("Destination Host Unreachable" versus "Could not resolve host"). DNS holds more than A records: TXT, PTR, CNAME (`intranet.corp.local` is a CNAME), MX and so on.

## Stage 3: Something is in the path (300 pts)

1. Ping works but the web page does not:
   ```
   ping -c2 portal.corp.local                 # replies
   curl -m 5 http://portal.corp.local         # curl: (28) Connection timed out
   sudo nmap -Pn -p 80 portal.corp.local      # 80/tcp filtered
   ```
   "Filtered" means no reply at all (packets dropped). "Closed" would be a TCP RST. Something drops TCP/80 but allows ICMP.
2. Locate it:
   ```
   traceroute -n portal.corp.local                # 1 10.10.10.1, 2 172.16.20.80
   sudo traceroute -T -p 80 -n portal.corp.local  # 1 10.10.10.1, then * * *
   ```
   The TCP/80 traffic dies right after the router, so the router is filtering it.
3. Look at the router's services:
   ```
   sudo nmap 10.10.10.1   # 23/tcp open telnet
   ```
   `telnet 10.10.10.1` asks for a username and password, which the student does not have.
4. Sniff the admin's login. The admin PC (10.10.10.30) logs in every ~30 seconds and the switch port floods all frames to the workstation:
   ```
   sudo tcpdump -i eth0 -n -A port 23
   ```
   Within 30 seconds the capture shows `netadmin` and a password of the form `C0rpNet!1234` in cleartext. The 4 digits are different for every student.
5. Log in:
   ```
   telnet 10.10.10.1
   Username: netadmin
   Password: C0rpNet!<digits from the capture>
   ```
   The post-login banner shows **flag 3**.

Teaching point: telnet, FTP and HTTP basic auth send credentials in cleartext. Anyone who can see the traffic (a mirror/SPAN port, a hub, a compromised switch, ARP spoofing) can read them. The fix is SSH (and the banner even mentions change CHG-2302 to move to SSH).

## Stage 4: Fix the root cause (400 pts)

1. On RTR-01, look at the ACL and its hit counters. Run the `curl` again from a second terminal tab and watch line 50 go up:
   ```
   RTR-01#show access-lists
   Extended IP access list LAN-IN
       20 permit icmp 10.10.10.0 0.0.0.255 any
       30 permit udp 10.10.10.0 0.0.0.255 host 172.16.20.53 eq domain
       40 permit tcp 10.10.10.0 0.0.0.255 host 172.16.20.53 eq domain
       50 deny tcp 10.10.10.0 0.0.0.255 host 172.16.20.80 eq www (6 matches)
       60 permit ip 10.10.10.0 0.0.0.255 any
   ```
2. Find out why it is there:
   ```
   RTR-01#show logging          # jsmith added line 50 under CHG-2231
   RTR-01#show running-config   # remark: "block portal during maintenance window. REMOVE AFTER!"
   ```
3. Remove the leftover rule:
   ```
   RTR-01#configure terminal
   RTR-01(config)#ip access-list extended LAN-IN
   RTR-01(config-ext-nacl)#no 50
   RTR-01(config-ext-nacl)#end
   RTR-01#show access-lists
   RTR-01#exit
   ```
4. Verify from the workstation:
   ```
   curl http://portal.corp.local
   ```
   The portal page shows **flag 4**. The ticket is resolved.

Other fixes also work and make good discussion points:

- Adding a permit above line 50, for example `45 permit tcp 10.10.10.0 0.0.0.255 host 172.16.20.80 eq www`, works but leaves dead config behind.
- `interface g0/0` then `no ip access-group LAN-IN in`, or `no ip access-list extended LAN-IN`, also gets the flag but removes all filtering. Least privilege says that is the wrong fix.
- Deleting line 60 triggers the implicit deny at the end of every ACL and breaks DNS and ping. The student can fix it or click **Reset lab**.

The router CLI accepts common IOS abbreviations (`sh ip int br`, `sh run`, `conf t`, `sh access-lists`), `?` for help, `do` in config mode, `ping`, `show ip arp`, `show ip route` and `show users`.

## Discussion questions

1. Why could the workstation reach the printer but not the DNS server before the fix?
2. What does INCOMPLETE or FAILED in `ip neigh` tell you, and at which OSI layer is that?
3. What is the difference between "filtered" and "closed" in nmap, and between a timeout and "connection refused" in curl?
4. Why does a successful ping not prove that a web application is reachable?
5. Which protocol should replace telnet, and what else would stop the credential capture?
6. Which change-management step failed with CHG-2231?
7. Map the work you did to the CompTIA troubleshooting methodology (identify the problem, establish a theory, test it, plan, implement, verify, document).

## Instructor notes

- The instructor view lists every student with username, password, flags solved, lab state and last activity. It can reset or stop any student's lab, stop all labs, and close new credential claims once everyone has theirs.
- A student who lost their credentials: look them up in the instructor view, then they use **Sign in** on the welcome page.
- Capacity: a 1 vCPU / 1 GB RAM server (with 2 GB swap) handled 14 labs with 12 students logged in and scanning at the same time, with about 330 MB RAM still free. Each active student uses roughly 18 MB. See the capacity table in [README.md](README.md).
