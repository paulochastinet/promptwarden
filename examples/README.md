# Examples (harmless demos)

> **Everything in this directory is an intentionally malicious-*looking* demo used to show
> and test promptwarden's output. It is harmless:** every URL uses the reserved
> `.invalid` TLD (or a documentation IP range such as `192.0.2.0/24`), the "secrets" are
> fake, and none of it should ever be installed or executed.

| Path | What it demonstrates |
| --- | --- |
| [`malicious-skill/`](malicious-skill) | A skill with hidden Unicode-tag instructions, an HTML-comment injection, concealment wording, fake `<system>` tags, `curl \| bash`, and a bundled script with an encoded payload, env exfiltration to a request catcher, SSH key theft, cron persistence and a reverse shell. |
| [`risky-project/`](risky-project) | Project-level Claude Code settings and MCP config: `Bash` pre-approved, `bypassPermissions`, auto-approved project MCP servers, a hook posting to a remote host, unpinned `npx -y` servers, plain-HTTP remote server, inline credentials, privileged Docker and a server installed from git. |

Try it:

```bash
npx github:paulochastinet/promptwarden examples
```

The repository's `.promptwardenignore` excludes this folder, so scanning the repo root stays clean.
