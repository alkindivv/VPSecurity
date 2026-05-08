---
name: vps-security-incident-response
description: Use when auditing, investigating, or hardening a Linux VPS after suspected unauthorized access, exposed ports, SSH key compromise, Cloudflare Tunnel/Tailscale exposure, or public AI/API gateway exposure. Evidence-first, fail-safe workflow for AI agents managing servers.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [vps, security, incident-response, ssh, firewall, cloudflare-tunnel, tailscale, linux-hardening]
    related_skills: [systematic-debugging, github-auth]
---

# VPS Security Incident Response

## Overview

This skill is a practical, evidence-first playbook for investigating and hardening a Linux VPS after suspected compromise or unsafe exposure.

The workflow is designed for AI agents operating over SSH or terminal tools. It prioritizes preserving access, verifying every claim, collecting concrete evidence, and making reversible changes where possible.

Core rule:

> Do not assume a server is safe because a config file says so. Verify effective config, live sockets, logs, process state, and external reachability.

## When to Use

Use this skill when the user asks about:

- “Is my server safe?”
- “Are my ports exposed?”
- “Was I hacked?”
- SSH brute-force or unknown login IPs
- SSH key rotation after compromise
- Cloudflare Tunnel / Tailscale / public API exposure
- Open ports such as `3000`, `3001`, `5173`, `8000`, `8080`, `20128`
- Removing dev servers exposed to the internet
- Checking persistence/backdoors after unauthorized root access
- Hardening a VPS without rebuilding immediately

Do not use this skill for:

- Offensive intrusion
- Stealth persistence
- Bypassing authentication
- Evading detection
- Exploiting third-party systems

## Safety Rules

### 1. Never lock yourself out

Before changing SSH, firewall, keys, or access controls:

- Confirm at least one active admin session exists.
- Add the new key before removing the old key.
- Test a new login before deleting the old key.
- Validate SSH config with `sshd -t` before restart.
- Prefer `systemctl restart sshd` only after validation.

Evidence commands:

```bash
who
w
ss -tnp | grep ':22' || true
sshd -t
sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication|maxauthtries|logingracetime|port)'
```

### 2. Treat root compromise as full compromise

If an unauthorized party had root access:

- All secrets on disk may be exposed.
- SSH keys, API keys, provider tokens, tunnel credentials, and app secrets must be rotated.
- A clean rebuild is the highest-confidence recovery.
- Hardening the existing VPS is acceptable for dev/sandbox, but do not call it “guaranteed clean.”

### 3. Evidence before action

For every claim, capture:

- command used
- output snippet
- timestamp if relevant
- severity
- recommendation

Avoid vague claims like “looks suspicious.” Say exactly why.

### 4. Prefer reversible changes

Before overwriting important config:

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)
cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak.$(date +%Y%m%d_%H%M%S)
cp /root/.cloudflared/config.yml /root/.cloudflared/config.yml.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
```

## Phase 0 — Triage Summary

Start with a short risk statement:

- Current risk: OK / LOW / MEDIUM / HIGH / CRITICAL
- Why
- Immediate dangerous findings
- Whether any changes have already been made

Quick triage command:

```bash
echo "=== TIME ==="; date -Is
echo "=== HOST ==="; hostname; whoami
echo "=== USERS ==="; who; w
echo "=== LISTENING PORTS ==="; ss -tulpen
echo "=== SSH EFFECTIVE CONFIG ==="; sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|logingracetime)'
echo "=== AUTHORIZED KEYS ==="; ls -la /root/.ssh/authorized_keys 2>/dev/null; cat /root/.ssh/authorized_keys 2>/dev/null
echo "=== ACTIVE SSH ==="; ss -tnp | grep ':22' || true
echo "=== FAIL2BAN ==="; fail2ban-client status 2>/dev/null || true
```

## Phase 1 — Identity and SSH Audit

### Check active sessions

```bash
who
w
ss -tnp | grep ':22' || true
last -i | head -50
lastb -i | head -50
```

Compare successful login IPs to the user’s allowlist.

If unknown IPs logged in successfully with public key, treat the old private key as compromised.

### Check SSH config correctly

Do not trust only `/etc/ssh/sshd_config`. Cloud-init and drop-in files may override it.

Check both raw and effective config:

```bash
echo "=== raw ssh config ==="
grep -RniE '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|LoginGraceTime|Include)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true

echo "=== effective ssh config ==="
sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication|maxauthtries|logingracetime|port|authorizedkeysfile)'
```

Danger signs:

- `passwordauthentication yes`
- `permitrootlogin yes`
- unknown keys in `authorized_keys`
- active sessions from unknown IPs
- root password status `P`

Check account status:

```bash
passwd -S root
awk -F: '$3==0 {print}' /etc/passwd
awk -F: '$7 ~ /(bash|sh|zsh)$/ {print}' /etc/passwd
getent group sudo admin wheel 2>/dev/null || true
```

## Phase 2 — SSH Key Rotation Protocol

Use this if the user confirms unknown successful SSH logins.

### User creates a new key locally

For macOS/Linux user:

```bash
ssh-keygen -t ed25519 -C "<user-machine-name>"
cat ~/.ssh/id_ed25519.pub
```

Tell the user:

- Send only the public key (`.pub`).
- Never send private key.
- Keep the current terminal open until new login is tested.

### Add new key first

```bash
cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak.$(date +%Y%m%d_%H%M%S)
printf '%s\n' '<NEW_PUBLIC_KEY>' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chown root:root /root/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

Ask the user to test from their laptop:

```bash
ssh -i ~/.ssh/id_ed25519 root@<SERVER_IP>
```

Only after they confirm login works, remove old keys:

```bash
printf '%s\n' '<NEW_PUBLIC_KEY>' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chown root:root /root/.ssh/authorized_keys
```

### Disable SSH password auth effectively

Edit both main config and cloud-init drop-ins if present:

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)
sed -i 's/^PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

grep -q '^PasswordAuthentication' /etc/ssh/sshd_config \
  && sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config \
  || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config

grep -q '^MaxAuthTries' /etc/ssh/sshd_config \
  && sed -i 's/^MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config \
  || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config

grep -q '^LoginGraceTime' /etc/ssh/sshd_config \
  && sed -i 's/^LoginGraceTime .*/LoginGraceTime 30/' /etc/ssh/sshd_config \
  || echo 'LoginGraceTime 30' >> /etc/ssh/sshd_config

# Cloud-init commonly overrides PasswordAuthentication.
if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
  cp /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/50-cloud-init.conf.bak.$(date +%Y%m%d_%H%M%S)
  printf 'PasswordAuthentication no\n' > /etc/ssh/sshd_config.d/50-cloud-init.conf
fi

sshd -t
systemctl restart sshd
sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication|maxauthtries|logingracetime)'
```

Optional after key login verified:

```bash
passwd -l root
passwd -S root
```

## Phase 3 — Port and Firewall Audit

### Identify listening services

```bash
ss -tulpen
ss -tlnp | sort
```

For specific suspicious ports:

```bash
for p in 3001 5173 20128 8000 8080; do
  echo "=== PORT $p ==="
  ss -tlnp | grep ":$p" || echo "not listening"
done
```

Map PID to process:

```bash
PID=<pid>
ps -p "$PID" -o pid,ppid,user,lstart,cmd --no-headers
pstree -p -s "$PID" 2>/dev/null || true
```

Danger signs:

- dev servers (`vite`, `next dev`, `webpack`, `uvicorn --reload`) bound to `0.0.0.0`
- dashboards exposed publicly
- raw app ports exposed when Cloudflare/Tailscale should be the only route
- Docker-published ports you did not expect

### Check firewall state

```bash
ufw status verbose 2>/dev/null || true
iptables -S
ip6tables -S
nft list ruleset 2>/dev/null | sed -n '1,220p'
```

### Restrict sensitive app ports

Pattern: allow localhost, allow Tailscale for admin port, drop everything else.

Example for port `20128`:

```bash
mkdir -p /etc/iptables

iptables -C INPUT -i lo -p tcp --dport 20128 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -p tcp --dport 20128 -j ACCEPT
iptables -C INPUT -i tailscale0 -p tcp --dport 20128 -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -i tailscale0 -p tcp --dport 20128 -j ACCEPT
iptables -C INPUT -p tcp --dport 20128 -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 20128 -j DROP

ip6tables -C INPUT -i lo -p tcp --dport 20128 -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -i lo -p tcp --dport 20128 -j ACCEPT
ip6tables -C INPUT -i tailscale0 -p tcp --dport 20128 -j ACCEPT 2>/dev/null || ip6tables -I INPUT 2 -i tailscale0 -p tcp --dport 20128 -j ACCEPT
ip6tables -C INPUT -p tcp --dport 20128 -j DROP 2>/dev/null || ip6tables -A INPUT -p tcp --dport 20128 -j DROP

iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
```

Persist restore on boot:

```bash
cat > /etc/systemd/system/iptables-restore.service <<'EOF'
[Unit]
Description=Restore iptables/ip6tables rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/sbin/iptables-restore /etc/iptables/rules.v4; /sbin/ip6tables-restore /etc/iptables/rules.v6'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iptables-restore.service
```

## Phase 4 — Cloudflare Tunnel and Tailscale Audit

### Check Tailscale

```bash
tailscale status 2>/dev/null || true
tailscale ip -4 2>/dev/null || true
tailscale funnel status 2>/dev/null || true
tailscale serve status 2>/dev/null || true
```

If dashboard is intended to be private, prefer Tailscale URL/IP:

```text
http://<TAILSCALE_IP>:<PORT>/dashboard
```

### Check Cloudflare Tunnel

```bash
systemctl status cloudflared* --no-pager 2>/dev/null || true
find /root/.cloudflared /etc/cloudflared -maxdepth 2 -type f -print 2>/dev/null
cat /root/.cloudflared/config.yml 2>/dev/null || true
```

Danger signs:

- tunnel exposes dashboard/login publicly
- tunnel maps multiple hostnames to the same unrestricted app
- service uses binary from `/tmp`
- stale quick tunnel service still enabled

### API-only public tunnel pattern

If the public domain should expose only API `/v1/*`, not dashboard:

```yaml
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json
protocol: http2
retries: 5

ingress:
  - hostname: api.example.com
    path: ^/v1/.*
    service: http://localhost:20128
    originRequest:
      noTLSVerify: true
      connectTimeout: 30s
  - service: http_status:404
```

Then:

```bash
systemctl restart cloudflared-<name>.service
```

Verify:

```bash
curl -sS -m 10 -o /tmp/api_models.txt -w 'api models http:%{http_code} size:%{size_download}\n' https://api.example.com/v1/models
curl -sS -m 10 -o /tmp/api_dash.txt -w 'api dashboard http:%{http_code} size:%{size_download}\n' https://api.example.com/dashboard
curl -sS -m 10 -o /tmp/api_login.txt -w 'api login http:%{http_code} size:%{size_download}\n' https://api.example.com/login
```

Expected:

- `/v1/models`: `200` or expected API response
- `/dashboard`: `404`
- `/login`: `404`

### Remove stale `/tmp` tunnel service

If a systemd service runs `/tmp/cloudflared`, disable it unless explicitly required:

```bash
systemctl stop 9router-tunnel.service 2>/dev/null || true
systemctl disable 9router-tunnel.service 2>/dev/null || true
mv /etc/systemd/system/9router-tunnel.service /root/9router-tunnel.service.disabled.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
systemctl daemon-reload
rm -f /tmp/cloudflared
```

## Phase 5 — Persistence and Backdoor Audit

### Cron

```bash
echo "=== user crontabs ==="
for u in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$u" 2>/dev/null && echo "--- user: $u ---"
done

echo "=== system cron ==="
cat /etc/crontab 2>/dev/null || true
ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
```

### Systemd

```bash
systemctl list-unit-files --type=service --state=enabled
systemctl list-timers --all
find /etc/systemd/system /usr/lib/systemd/system -type f -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort
```

### Shell and login persistence

```bash
for f in /root/.bashrc /root/.profile /root/.bash_profile /etc/profile /etc/bash.bashrc /etc/rc.local /etc/ld.so.preload; do
  echo "=== $f ==="
  [ -e "$f" ] && sed -n '1,220p' "$f" || echo "missing"
done

find /root /home -path '*/.ssh/*' -maxdepth 4 -type f -print -exec ls -la {} \; 2>/dev/null
```

### PAM and sudoers

```bash
grep -RniE 'pam_exec|pam_python|pam_permit|NOPASSWD|authorized_keys|curl|wget|nc|bash -i' /etc/pam.d /etc/sudoers /etc/sudoers.d 2>/dev/null || true
```

## Phase 6 — Filesystem and Malware Indicators

### Recent changes

Use date based on suspected compromise date:

```bash
SINCE='2026-04-28'
for d in /etc /root /usr/local /opt /var/tmp /tmp /dev/shm; do
  echo "=== recent files in $d ==="
  find "$d" -xdev -newermt "$SINCE" -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null | sort | head -300
 done
```

Exclude huge caches if needed:

```bash
find /root -xdev \
  -path /root/.cache -prune -o \
  -path /root/.npm -prune -o \
  -path /root/.local/share -prune -o \
  -newermt '2026-04-28' \
  -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null | sort | head -500
```

### SUID/SGID

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null | sort
```

Danger signs:

- SUID shell in `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/local/bin`
- recently modified system binaries
- unknown executable owned by root in writable directories

### Miner/rootkit quick scan

```bash
ps auxww | grep -Ei 'xmrig|kinsing|kdevtmpfsi|watchdog|masscan|pnscan|minerd|cryptonight|stratum|kinsing|ziggy' | grep -v grep || true
find /tmp /var/tmp /dev/shm -type f -perm /111 -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\n' 2>/dev/null | sort
```

### Package integrity

If available:

```bash
command -v debsums >/dev/null && debsums -s || echo 'debsums not installed'
```

If not installed and user approves:

```bash
apt-get update && apt-get install -y debsums
```

## Phase 7 — Docker Audit

```bash
docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Ports}}' 2>/dev/null || true
docker ps -a --format 'table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true
docker images 2>/dev/null || true
docker network ls 2>/dev/null || true
docker volume ls 2>/dev/null || true
```

Danger signs:

- unknown privileged containers
- host network containers
- published admin ports
- containers restarting automatically from unknown images

## Phase 8 — External Reachability Tests

From the server itself, direct public-IP tests may not perfectly simulate the internet, but they are still useful.

```bash
PUBLIC_IP=$(curl -sS -m 5 https://ifconfig.me 2>/dev/null || true)
echo "$PUBLIC_IP"
for p in 22 3001 5173 20128; do
  timeout 5 bash -c "</dev/tcp/$PUBLIC_IP/$p" >/dev/null 2>&1 && echo "OPEN $p" || echo "CLOSED/FILTERED $p"
done
```

Prefer also testing from another machine or online port scanner if appropriate.

## Phase 9 — Reporting Format

Use concise, non-alarmist reporting:

```text
Status: HIGH
Reason: old SSH key used by unknown IPs; password auth was effectively on; public dev ports exposed.

Fixed:
- rotated SSH key
- disabled effective password auth
- killed unknown SSH sessions
- blocked 3001/5173/20128 from public direct access

Still risky:
- secrets on disk may be exposed
- root compromise cannot be proven clean without rebuild

Evidence:
- sshd -T: passwordauthentication no
- authorized_keys: only alkindi-macbook
- ss: 3001/5173 not listening
- Cloudflare: only /v1/* forwarded

Next:
- rotate API keys/tokens
- consider rebuild if production
```

## Decision Guide

### If unknown successful root login happened

Severity: CRITICAL before containment, HIGH after containment.

Actions:

1. Rotate SSH key.
2. Disable password auth effectively.
3. Kill unknown active sessions.
4. Block known malicious IPs.
5. Audit persistence.
6. Rotate all secrets.
7. Recommend rebuild for production.

### If only failed brute-force attempts happened

Severity: MEDIUM.

Actions:

1. Ensure password auth off.
2. Ensure fail2ban active.
3. Consider SSH allowlist/Tailscale-only SSH.
4. Monitor logs.

### If dev port is publicly exposed

Severity: HIGH if unauthenticated dashboard/API; MEDIUM if authenticated.

Actions:

1. Kill unused dev server.
2. Bind to localhost or firewall it.
3. Use Tailscale for admin UI.
4. Use Cloudflare Tunnel only for intended public API paths.

### If Cloudflare Tunnel exposes dashboard

Severity: MEDIUM-HIGH.

Actions:

1. Restrict tunnel path to API only.
2. Return 404 for dashboard/login/root.
3. Access dashboard via Tailscale.
4. Add Cloudflare Access or WAF/rate limits if needed.

## Common Pitfalls

1. **Trusting `/etc/ssh/sshd_config` but not `sshd -T`.**
   Cloud-init drop-ins can override the main file. Always verify effective config.

2. **Removing the old SSH key before testing the new key.**
   This can lock out the user. Add first, test, then remove.

3. **Blocking port 20128 without allowing localhost.**
   Cloudflare tunnel often connects to `localhost`; blocking loopback breaks it.

4. **Forgetting IPv6.**
   IPv4 firewall can be correct while IPv6 remains open. Check `ip6tables` and `ss` for `[::]` listeners.

5. **Leaving quick tunnel services from `/tmp`.**
   Permanent systemd services should not run binaries from `/tmp`.

6. **Calling a compromised server clean.**
   After root compromise, you can reduce risk, but only rebuild gives high confidence.

7. **Exposing dashboard and API on the same public tunnel.**
   Prefer public `/v1/*` API only, dashboard via Tailscale/private network.

8. **Printing secrets in the report.**
   Report file paths and key IDs, not token values.

## Verification Checklist

- [ ] Active admin session confirmed before changes
- [ ] New SSH key added and tested before old key removal
- [ ] `authorized_keys` contains only expected keys
- [ ] `sshd -T` shows `passwordauthentication no`
- [ ] `sshd -T` shows `permitrootlogin without-password` or stricter
- [ ] Unknown SSH sessions killed or explained
- [ ] `last -i` reviewed against allowlist
- [ ] `lastb -i` reviewed for brute-force intensity
- [ ] Sensitive public ports reviewed with `ss -tulpen`
- [ ] Dev ports killed or firewalled
- [ ] IPv4 and IPv6 firewall rules reviewed
- [ ] Firewall rules persist after reboot
- [ ] Cloudflare Tunnel exposes only intended host/path
- [ ] Dashboard is private via Tailscale or Cloudflare Access
- [ ] Stale `/tmp` services disabled
- [ ] Cron/systemd persistence reviewed
- [ ] SUID/SGID anomalies reviewed
- [ ] `/tmp`, `/var/tmp`, `/dev/shm` reviewed
- [ ] Docker containers/images/ports reviewed
- [ ] Secrets rotation recommended after any root compromise
- [ ] Final report separates fixed vs still-risky vs recommended next steps
