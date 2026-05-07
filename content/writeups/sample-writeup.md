---
title: "HTB: [Machine Name] — Walkthrough"
date: 2025-05-01
summary: "A realistic-feeling AD environment with a credential-spray foothold and a Kerberos-based path to Domain Admin."
tags: ["htb", "active-directory", "kerberos"]
draft: false
---

> Replace this file with your real writeup. The structure below is a starting template I find useful — feel free to reorganize.

## Recon

Initial nmap scan revealed the usual AD suspects:

```bash
nmap -sC -sV -p- 10.10.10.10
```

Key ports observed: 53 (DNS), 88 (Kerberos), 389 (LDAP), 445 (SMB), 5985 (WinRM).

## Foothold

Walk through how the initial access was achieved. Be specific about the *thinking*, not just the commands:

- What did you notice first?
- What did you try and discard, and why?
- What worked?

```bash
# Example command block
crackmapexec smb 10.10.10.10 -u users.txt -p 'Spring2024!'
```

## Privilege Escalation

Document the path from initial user to higher privilege. Screenshots help here.

## Domain Admin

The final step — and the lesson learned.

## Takeaways

- One thing this box reinforced: ...
- A defender could have prevented this by: ...
- A tool I'll keep in my notes: ...
