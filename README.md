# 🛡️ osqueryi Blue Team Cheat Sheet — Linux Logs & Threat Hunting

> **osqueryi** lets you query your Linux system like a database using SQL. This cheat sheet focuses on **blue teaming**, **incident response**, and **Linux log analysis**.

---

## 🚀 Launching osqueryi

```bash
osqueryi                          # Start interactive shell (run as root for full data)
sudo osqueryi                     # Recommended — root access for all tables
osqueryi --json                   # Output as JSON
osqueryi "SELECT * FROM users"    # One-off query from terminal
```

---

## 🖥️ Shell Meta-Commands

| Command | Description |
|---|---|
| `.tables` | List all available tables |
| `.tables process` | Search tables by keyword |
| `.schema <table>` | Show columns & types for a table |
| `.mode pretty` | Pretty table output (default) |
| `.mode json` | JSON output |
| `.mode csv` | CSV output |
| `.timer on` | Show query execution time |
| `.quit` | Exit the shell |

---

## 🔍 Attack Surface — Enumeration

### System Info
```sql
-- Basic system fingerprint
SELECT hostname, cpu_brand, physical_memory, hardware_model FROM system_info;

-- OS version
SELECT name, version, platform, build FROM os_version;

-- Uptime (check for unexpected reboots)
SELECT days, hours, minutes FROM uptime;
```

### Users & Groups
```sql
-- All local user accounts
SELECT uid, gid, username, description, directory, shell FROM users;

-- Look for non-standard shells or suspicious home dirs
SELECT username, shell, directory FROM users
  WHERE shell NOT IN ('/bin/bash', '/bin/sh', '/usr/sbin/nologin', '/bin/false');

-- All groups
SELECT gid, groupname FROM groups;

-- Users with sudo / admin group membership
SELECT u.username, g.groupname
  FROM users u JOIN groups g ON u.gid = g.gid
  WHERE g.groupname IN ('sudo', 'wheel', 'adm', 'root');
```

### Open Ports & Listening Services
```sql
-- All listening ports
SELECT pid, port, protocol, address FROM listening_ports;

-- Listening ports with process names
SELECT lp.pid, p.name, lp.port, lp.protocol, lp.address
  FROM listening_ports lp
  JOIN processes p ON lp.pid = p.pid
  ORDER BY lp.port;

-- Ports exposed on all interfaces (0.0.0.0) — high risk
SELECT lp.port, lp.protocol, p.name, p.path
  FROM listening_ports lp
  JOIN processes p ON lp.pid = p.pid
  WHERE lp.address = '0.0.0.0';
```

---

## 🔥 Incident Response — Processes

### Suspicious Process Investigation
```sql
-- All running processes
SELECT pid, ppid, name, path, cmdline, uid FROM processes;

-- Processes running as root
SELECT pid, name, path, cmdline FROM processes WHERE uid = 0;

-- Processes with no on-disk path (potential fileless malware)
SELECT pid, name, cmdline, uid FROM processes WHERE path = '';

-- Processes with network connections (high-value pivot)
SELECT p.pid, p.name, p.path, s.local_address, s.local_port,
       s.remote_address, s.remote_port, s.state
  FROM processes p
  JOIN process_open_sockets s ON p.pid = s.pid
  WHERE s.remote_address != ''
    AND s.remote_address != '127.0.0.1'
    AND s.remote_address != '::1';

-- Specific PID investigation
SELECT pid, fd, socket, local_address, remote_address
  FROM process_open_sockets WHERE pid = <PID>;

-- Parent-child process relationships (spot unusual spawns)
SELECT p.pid, p.name, p.cmdline, pp.name AS parent_name, pp.cmdline AS parent_cmd
  FROM processes p
  JOIN processes pp ON p.ppid = pp.pid
  WHERE p.name IN ('bash', 'sh', 'python', 'python3', 'perl', 'nc', 'ncat', 'curl', 'wget');
```

### Open Files by Process
```sql
-- Files opened by a specific PID
SELECT pid, fd, path FROM process_open_files WHERE pid = <PID>;

-- All open files (look for /tmp, /dev/shm — common malware staging)
SELECT p.name, p.pid, f.path
  FROM process_open_files f
  JOIN processes p ON f.pid = p.pid
  WHERE f.path LIKE '/tmp/%'
     OR f.path LIKE '/dev/shm/%'
     OR f.path LIKE '/var/tmp/%';
```

---

## 🔥 Incident Response — Network

### Active Connections
```sql
-- All established network connections
SELECT pid, local_address, local_port, remote_address, remote_port, state
  FROM process_open_sockets
  WHERE state = 'ESTABLISHED';

-- Connections with process context
SELECT p.name, p.pid, p.path, s.remote_address, s.remote_port, s.state
  FROM process_open_sockets s
  JOIN processes p ON s.pid = p.pid
  WHERE s.state = 'ESTABLISHED'
    AND s.remote_address NOT IN ('127.0.0.1', '::1', '');

-- DNS / port 53 queries being made
SELECT p.name, p.pid, s.remote_address, s.remote_port
  FROM process_open_sockets s
  JOIN processes p ON s.pid = p.pid
  WHERE s.remote_port = 53;
```

### Network Interfaces
```sql
-- All interfaces and IP addresses
SELECT interface, address, mask, broadcast FROM interface_addresses;

-- Interface details
SELECT interface, mac, type, mtu FROM interface_details WHERE mac != '00:00:00:00:00:00';
```

---

## 💀 Persistence Detection

### Cron Jobs
```sql
-- All cron jobs for all users
SELECT command, path, minute, hour, day_of_month, month, day_of_week FROM crontab;

-- Cron jobs pointing to suspicious locations
SELECT command, path FROM crontab
  WHERE command LIKE '%/tmp/%'
     OR command LIKE '%/dev/shm/%'
     OR command LIKE '%curl%'
     OR command LIKE '%wget%'
     OR command LIKE '%bash -i%'
     OR command LIKE '%nc %';
```

### Startup Services
```sql
-- All systemd services (look for unexpected entries)
SELECT name, source, status, pid FROM services;

-- Running services only
SELECT name, status, pid FROM services WHERE status = 'RUNNING';

-- Stopped but enabled services (persistence candidates)
SELECT name, status FROM services WHERE status != 'RUNNING';
```

### Authorized Keys & SSH
```sql
-- SSH authorized keys (backdoor check)
SELECT username, key_file, key, key_type, comment
  FROM user_ssh_keys;

-- SSHD config settings
SELECT name, value FROM augeas WHERE path = '/files/etc/ssh/sshd_config';
```

### Login Items & Shell Config
```sql
-- Shell history files (look for attacker commands)
SELECT uid, shell, directory FROM users;
-- Then manually: cat /home/<user>/.bash_history

-- Environment variables (can reveal injected paths)
SELECT pid, key, value FROM process_envs WHERE key IN ('PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH');

-- LD_PRELOAD abuse (library injection / rootkit technique)
SELECT pid, key, value FROM process_envs WHERE key = 'LD_PRELOAD';
```

---

## 📁 File Integrity & Disk Forensics

### Critical Config Files
```sql
-- Hash critical system files to detect tampering
SELECT path, sha256, size, mtime
  FROM hash
  WHERE path IN (
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/group',
    '/etc/hosts',
    '/etc/crontab'
  );

-- Files recently modified in /etc (last 24h = 86400 seconds)
SELECT path, size, mtime, mode
  FROM file
  WHERE directory = '/etc'
    AND mtime > (SELECT unix_time - 86400 FROM time);

-- SUID/SGID files (privilege escalation vectors)
SELECT path, mode, uid, gid FROM file
  WHERE (mode LIKE '%4%' OR mode LIKE '%2%')
    AND (directory LIKE '/usr/%' OR directory LIKE '/bin%' OR directory LIKE '/sbin%');
```

### Suspicious Files in Staging Directories
```sql
-- Executables dropped in /tmp, /dev/shm, /var/tmp
SELECT path, size, sha256, mtime FROM file
  WHERE (directory = '/tmp'
      OR directory = '/dev/shm'
      OR directory = '/var/tmp')
    AND (path LIKE '%.sh'
      OR path LIKE '%.py'
      OR path LIKE '%.elf'
      OR path LIKE '%.bin');
```

### Installed Packages (Debian/Ubuntu)
```sql
-- All installed packages
SELECT name, version, source, status FROM deb_packages;

-- Search for a specific suspicious package
SELECT name, version, install_time FROM deb_packages WHERE name LIKE '%<suspicious>%';

-- Recently installed packages (cross-reference with incident timeline)
SELECT name, version, install_time FROM deb_packages ORDER BY install_time DESC LIMIT 20;
```

---

## 📜 Log Analysis Support Queries

> Pair osquery with these log file locations for full coverage.

| Log File | Location | What to Look For |
|---|---|---|
| Authentication | `/var/log/auth.log` | Failed logins, `useradd`, `sudo` abuse |
| System messages | `/var/log/syslog` | Service crashes, kernel errors |
| Package installs | `/var/log/dpkg.log` | Unexpected package installs |
| Kernel messages | `/var/log/kern.log` | Kernel-level anomalies |
| Cron execution | `/var/log/cron.log` | Scheduled task execution |

### Supplementary Log Commands (bash)
```bash
# Failed login attempts
cat /var/log/auth.log | grep "Failed password"

# Successful logins
cat /var/log/auth.log | grep "Accepted"

# New user accounts created
cat /var/log/auth.log | grep useradd

# Suspicious package installs
grep " install " /var/log/dpkg.log

# Suspicious service activity
cat /var/log/syslog | grep <service-name>

# Service journal (systemd)
sudo journalctl -u <service-name>
sudo journalctl --since "2024-01-01" --until "2024-01-02"
```

---

## 🎯 Quick Hunt Queries (Copy & Paste)

```sql
-- 1. Who is logged in right now?
SELECT liu.username, liu.host, liu.time, liu.tty FROM logged_in_users liu;

-- 2. Recent login history
SELECT username, host, time, type FROM last ORDER BY time DESC LIMIT 20;

-- 3. Processes connecting to the internet
SELECT p.name, p.pid, s.remote_address, s.remote_port
  FROM processes p JOIN process_open_sockets s ON p.pid = s.pid
  WHERE s.remote_address != '' AND s.remote_address NOT LIKE '127.%' AND s.remote_address NOT LIKE '::';

-- 4. New/unexpected user accounts
SELECT uid, username, shell, directory FROM users WHERE uid >= 1000;

-- 5. Accounts with no password (uid 0 check)
SELECT username, uid FROM users WHERE uid = 0;

-- 6. Suspicious cron jobs
SELECT command, path FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%' OR command LIKE '%/tmp/%';

-- 7. Services running from unusual paths
SELECT name, path FROM services WHERE path NOT LIKE '/usr/%' AND path NOT LIKE '/lib/%' AND path != '';

-- 8. Hash of a suspicious binary
SELECT path, sha256 FROM hash WHERE path = '/path/to/suspicious/file';

-- 9. Kernel modules loaded (rootkit check)
SELECT name, size, status FROM kernel_modules ORDER BY name;

-- 10. Active ESTABLISHED connections summary
SELECT p.name, s.remote_address, s.remote_port, COUNT(*) AS connections
  FROM process_open_sockets s JOIN processes p ON s.pid = p.pid
  WHERE s.state = 'ESTABLISHED'
  GROUP BY p.name, s.remote_address, s.remote_port
  ORDER BY connections DESC;
```

---

## 🗂️ Key Tables Reference

| Table | Description |
|---|---|
| `processes` | All running processes |
| `process_open_sockets` | Network connections per process |
| `process_open_files` | Files opened by processes |
| `process_envs` | Environment variables per process |
| `listening_ports` | Ports actively listening |
| `users` | Local user accounts |
| `groups` | Local groups |
| `logged_in_users` | Currently logged-in users |
| `last` | Login history |
| `crontab` | Scheduled cron jobs |
| `services` | Systemd services |
| `user_ssh_keys` | SSH authorized keys |
| `file` | File metadata queries |
| `hash` | File hashing (md5, sha1, sha256) |
| `deb_packages` | Installed Debian packages |
| `kernel_modules` | Loaded kernel modules |
| `interface_addresses` | Network interface IPs |
| `interface_details` | NIC details (MAC, MTU) |
| `system_info` | Hostname, CPU, RAM |
| `os_version` | OS name and version |
| `uptime` | System uptime |
| `augeas` | Config file parsing |

---

## 🔗 Resources

- [osquery Official Docs](https://osquery.readthedocs.io/)
- [osquery Schema Reference](https://osquery.io/schema/)
- [TryHackMe Linux IR Room](https://tryhackme.com)
- [Sigma Rules for osquery](https://github.com/SigmaHQ/sigma)

---

