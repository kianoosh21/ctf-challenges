# CTF challenges

Hands-on, CTF-style labs for IT and cybersecurity classes, grouped by course. Each lab is a self-contained Docker package: clone the repo, run one command, and students use it from their browser. Every student gets their own isolated environment, unique credentials and unique flags.

## Labs

### Network+

| # | Lab | Topics | Default ports | Folder |
|---|---|---|---|---|
| 01 | Portal outage (INC-4471) | IP configuration, ARP, DNS, packet capture, cleartext protocols, router ACLs | 8080, 8443 | [network-plus/lab01-portal-outage](network-plus/lab01-portal-outage/) |

### Security+

Security+ labs come in two tracks: **blue team** (defend, detect, respond) and **red team** (attack, exploit, report).

| Track | # | Lab | Topics | Default ports | Folder |
|---|---|---|---|---|---|
| Blue team | 01 | Web server incident (INC-5203) | Incident response, log analysis, IoCs, persistence, host firewall, file integrity, least privilege | 8081, 8444 | [security-plus/blue-team/lab01-web-server-incident](security-plus/blue-team/lab01-web-server-incident/) |

## Running a lab

You need [Docker](https://docs.docker.com/get-docker/) with Docker Compose v2.

```bash
git clone https://github.com/kianoosh21/ctf-challenges.git
cd ctf-challenges/<lab-folder>
docker compose up -d --build
docker compose logs netlab
```

The logs show the URLs and the instructor key. Each lab's README covers requirements, classroom setup, settings and troubleshooting. Labs have different default ports, so several can run on the same machine.

Solutions are in each lab's `SOLUTION.md`. They are spoilers, so students should not read them before the lab.
