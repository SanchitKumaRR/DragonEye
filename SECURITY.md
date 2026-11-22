# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| < 1.0 | no |

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in DragonEye itself.
Use GitHub's private vulnerability reporting on
<https://github.com/SanchitKumaRR/DragonEye/security/advisories/new>, or email
the maintainer listed in the repository profile. Include:

- affected version and platform
- a minimal reproduction
- what you expected the scope or safety model to prevent

You will get an acknowledgement within 7 days. Please give a reasonable
window to ship a fix before disclosure.

## Threat model

DragonEye is a **single-user, local tool** that runs untrusted scanners and
writes their output to disk. It is not a multi-tenant service.

What it does defend:

- **Scope is fail-closed.** A program with no in-scope rules refuses to run;
  unparseable rules fail before any traffic; deny rules beat allow rules;
  cloud metadata endpoints and private ranges are blocked by default.
- **Targets are filtered in one place** (`tools/runner.py`) before a tool is
  invoked, and every ingested asset and finding is re-checked against scope.
- **DNS answers are screened** after the `resolve` stage: a hostname that
  resolves into a deny CIDR, a private range or a metadata endpoint is dropped
  and audited.
- **No shell.** Tools are executed argv-only with timeouts and process-group
  kills; the LLM cannot run commands, only request a bounded local grep.
- **Local-only GUI.** Binds loopback by default, refuses remote binds without
  `--insecure-bind`, requires a per-process token for mutating requests, and
  returns API keys masked.

What it does **not** defend (by design or not yet built):

- **Network-level enforcement.** Filtering happens on the target list handed
  to a tool. A scanner can still follow a redirect, crawl a link, or resolve a
  CNAME to a host that was never approved. Katana is pinned to `fqdn` field
  scope and Nuclei runs with `-ni` (no OOB callbacks), but a scope-enforcing
  proxy (mitmproxy/Caido) is still on the roadmap. Do not treat DragonEye as a
  network firewall.
- **A malicious local user.** The GUI trusts anything that can read loopback
  and `~/.config/dragoneye/keys.json`. Keys are stored 0600 and the directory
  0700, but they are not encrypted at rest.
- **Scanner vulnerabilities.** Nuclei templates and third-party binaries are
  outside this project's trust boundary.

## Operational guidance

- Run on a machine or VM you are willing to expose to scanner traffic.
- Use `--dry-run` and `dragoneye scope` before a live run.
- Keep the GUI on loopback. If you need remote access, put it behind an SSH
  tunnel or a authenticated reverse proxy you control.
- Treat every finding as unverified until a human reproduces it.
- Only test assets you are authorised to test.
