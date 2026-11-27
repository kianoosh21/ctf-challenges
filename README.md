# CTF challenges

Hands-on, CTF-style labs for IT and cybersecurity classes. Each lab is a self-contained Docker package: clone the repo, run one command, and students use it from their browser.

## Labs

| Lab | Course | Topics | Setup | Folder |
|---|---|---|---|---|
| INC-4471: intranet portal outage | CompTIA Network+ | IP configuration, ARP, DNS, packet capture, cleartext protocols, router ACLs | Each student gets their own isolated network | [netplus-inc-4471](netplus-inc-4471/) |

## Running a lab

You need [Docker](https://docs.docker.com/get-docker/) with Docker Compose v2.

```bash
git clone https://github.com/kianoosh21/ctf-challenges.git
cd ctf-challenges/<lab-folder>
docker compose up -d --build
docker compose logs
```

The logs show the URL to open and any instructor key. Each lab's README covers requirements, classroom setup, settings and troubleshooting.

Solutions are in each lab's `SOLUTION.md`. They are spoilers, so students should not read them before the lab.
