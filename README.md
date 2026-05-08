# VPSecurity

Reusable Hermes/AI-agent security skills for investigating and hardening Linux VPS servers after suspected compromise.

## Skills

- `skills/devops/vps-security-incident-response/SKILL.md`
  - Deep security investigation workflow
  - SSH compromise response
  - Firewall / port hardening
  - Cloudflare Tunnel + Tailscale exposure review
  - Persistence/backdoor audit
  - Evidence-first reporting

## Core principle

Do not trust claims. Verify with commands, logs, config, and live service checks.

## Quick use

In a Hermes Agent environment, copy or reference the skill directory, then load:

```text
skill_view(name='vps-security-incident-response')
```

Then ask the agent to run an audit or hardening pass on the target VPS.

## Safety warning

This skill can include high-impact operations such as SSH config changes, firewall rules, service disablement, and password locking. Always keep at least one verified active admin session before changing access controls.
