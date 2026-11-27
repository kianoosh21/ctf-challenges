LAB_ID = 'secblue01'        # used in cookie names, must be unique per lab
TITLE = 'Security+ Blue Team Lab 01: Web server incident (INC-5203)'

UI = {
    'ticket': 'Ticket INC-5203',
    'hostname': 'web-01',
    'console': 'WEB-01 console',
    'console_sub': '(CorpNet DMZ, public web server)',
    'flag_example': 'SECP{...}',
    'launch_text': 'The server builds a private copy of the compromised web server and its network just for you.',
    'work_text': 'Log in to the server from the terminal on this page, investigate, contain, clean up and '
                 'recover. Stages 1 and 2 give flags, stages 3 and 4 are checked live.',
    'building_text': 'Restoring WEB-01 from the incident snapshot and building its network. '
                     'This takes about 10 to 30 seconds.',
}

BRIEFING = (
    'Ticket INC-5203: the EDR agent on WEB-01, CorpNet\'s public web server, reports periodic outbound '
    'HTTP connections to an unknown internet host. You are the on-call incident responder. Log in to '
    'WEB-01, confirm the compromise, work out how the attacker got in, contain and eradicate the threat, '
    'and recover the server without taking the website down. Flags look like SECP{...}.'
)

STAGES = [
    {
        'id': '1', 'points': 100, 'kind': 'flag',
        'title': 'Detect: find the beacon',
        'tag': 'Detection: processes, connections, packet capture',
        'desc': ('The EDR says WEB-01 talks to an unknown internet host about every 20 seconds. Find the '
                 'process responsible and the server it talks to. Capture its traffic or read the program it '
                 'runs: flag 1 travels inside every beacon.'),
        'hints': [
            'List processes as a tree: ps auxf. What does not belong on a web server? Kernel threads (names in '
            '[brackets]) never appear inside a container, so one that does is a disguise.',
            'Watch the traffic without the monitoring noise: sudo tcpdump -i eth0 -n -A \'tcp dst port 80 and not '
            'host 10.20.0.100\'. Or see what the process runs: cat /proc/<PID>/cmdline | tr \'\\0\' \' \'',
            'The beacon is an HTTP POST with a custom header. sudo tcpdump -i eth0 -n -A -c 30 \'tcp dst port 80 '
            'and not host 10.20.0.100\' | grep -a X-Session',
        ],
    },
    {
        'id': '2', 'points': 200, 'kind': 'flag',
        'title': 'Analyze: how did they get in?',
        'tag': 'Analysis: log review, indicators of compromise',
        'desc': ('Before cleaning up, scope the incident. The attacker logged in to WEB-01 from the internet. '
                 'Use the logs to find the attacker\'s IP address and the account they broke into. Submit flag 2 '
                 'as SECP{<attacker IP>_<account>}, for example SECP{192.0.2.10_alice}.'),
        'hints': [
            'SSH logins are in /var/log/auth.log. Count failed logins per source address: grep \'Failed password\' '
            '/var/log/auth.log | awk \'{print $(NF-3)}\' | sort | uniq -c | sort -rn',
            'A brute-force attack looks like many failures followed by one success from the same address: '
            'grep \'Accepted\' /var/log/auth.log. 10.20.0.x addresses are CorpNet\'s own staff and CI server.',
            'Look at what happened right after that login: grep -E \'sudo|useradd|Accepted\' /var/log/auth.log, '
            'and the account\'s shell history: sudo cat /home/<account>/.bash_history',
        ],
    },
    {
        'id': '3', 'points': 300, 'kind': 'check',
        'title': 'Contain and eradicate',
        'tag': 'Containment and eradication: host firewall, persistence, accounts',
        'desc': ('Contain first, then eradicate. Block WEB-01 from reaching the attacker\'s server, then remove '
                 'what the attacker left behind. If something comes back after you delete it, something is '
                 'reinstalling it: check your containment. Click Check my work to test the live server. Keep the '
                 'website up and do not lock yourself out (Reset lab rebuilds the server if you do).'),
        'checks': [
            ('c2_blocked', 'WEB-01 can no longer reach the attacker\'s server'),
            ('implant_stopped', 'The beacon process is no longer running'),
            ('implant_deleted', 'The beacon program is deleted from disk'),
            ('cron_clean', 'The scheduled task that restarts the beacon is removed'),
            ('no_uid0', 'The backdoor account with root privileges (UID 0) is removed'),
            ('key_removed', 'The attacker\'s SSH key is removed from every authorized_keys file'),
        ],
        'hints': [
            'Contain at the host firewall: sudo iptables -A OUTPUT -d <attacker server IP> -j DROP. Then stop the '
            'process: sudo kill <PID>. Back a minute later? Something restarts it: ls -la /etc/cron.d and compare '
            'with /opt/ir/README.txt.',
            'Accounts with UID 0 are root: awk -F: \'$3 == 0\' /etc/passwd. Remove the extra one with sudo userdel '
            '-f <name>. Never add -r here: that account\'s home directory is /root.',
            'Compare the keys with /opt/ir/README.txt: sudo cat /root/.ssh/authorized_keys '
            '/home/*/.ssh/authorized_keys. Delete unapproved key lines with sudo nano <file>, or '
            'sudo sed -i \'/<key comment>/d\' <file>.',
        ],
    },
    {
        'id': '4', 'points': 400, 'kind': 'check',
        'title': 'Recover: close the way back in',
        'tag': 'Recovery: integrity baselines, least privilege, credentials',
        'desc': ('The attacker turned a normal account into root through a misconfiguration and changed a file so '
                 'they could get back in. Use the known-good baselines in /opt/ir to find the change, restore the '
                 'file, fix the weakness, remove the root shell they left, and reset the compromised account\'s '
                 'password. Click Check my work when done.'),
        'checks': [
            ('script_clean', 'The tampered script is back to its known-good content'),
            ('script_perms', 'Only root can change that script (owned by root, not group or world writable)'),
            ('no_suid', 'The extra SUID root shell is removed'),
            ('creds_reset', 'The compromised account\'s password is changed or the account is locked'),
            ('site_up', 'The website still works for customers (tested from MON-01)'),
        ],
        'hints': [
            'Integrity check against the golden image: sudo sha256sum -c /opt/ir/baseline.sha256 | grep -v \': OK$\'. '
            'Read the changed file. A base64 string can be decoded with: echo \'<text>\' | base64 -d',
            'Restore it and fix who owns it: sudo cp /opt/ir/golden/<file> <path>, then sudo chown root:root <path> '
            'and sudo chmod 755 <path>. A script that root runs (from cron or sudo) must only be writable by root.',
            'Find SUID programs that are not in the baseline: sudo find / -xdev -perm -4000 -type f 2>/dev/null | '
            'sort | diff /opt/ir/suid-baseline.txt -. Remove the extra one. Then sudo passwd <account>, or lock it '
            'with sudo passwd -l <account>.',
        ],
    },
]

MAX_SCORE = sum(s['points'] for s in STAGES)
