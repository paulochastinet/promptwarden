# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |

## Reporting a vulnerability in promptwarden

Please **do not open a public issue** for vulnerabilities in promptwarden itself
(for example: a crafted file that crashes the scanner, makes it hang (ReDoS), executes code,
or leaks an unmasked secret into its output).

Instead, use GitHub's private reporting:
**[Report a vulnerability](https://github.com/paulochastinet/promptwarden/security/advisories/new)**.

Include a minimal reproducing file (use fake secrets and `.invalid` hosts), the command you ran,
and the promptwarden / Node.js versions. You can expect an acknowledgement within 72 hours and a
fix or mitigation plan within 14 days for confirmed issues.

## Detection gaps and bypasses

A malicious skill, rule or MCP config that promptwarden **fails to detect** is a detection gap,
not a vulnerability in the tool. Please open a
[new rule / detection gap issue](https://github.com/paulochastinet/promptwarden/issues/new?template=new_rule.yml)
— a harmless reproduction is enough. If the bypass is being actively exploited in the wild and
public disclosure would cause harm, report it privately using the link above.

## Scope and design notes

- promptwarden never executes, imports or evaluates scanned files. It only reads them as text
  (and parses JSON/TOML/YAML with data-only parsers).
- It makes no network requests.
- Secrets that match known formats are masked in every output format.
- It is a heuristic static scanner, **not a sandbox**: a clean result does not prove a skill or
  MCP server is safe. Review what you install.
