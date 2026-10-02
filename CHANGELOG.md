# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-02

### Added

- `promptwarden` CLI (`npx promptwarden [paths...]`) and programmatic API (`scan()`, `scanContent()`, formatters).
- Discovery of agent files: `SKILL.md` + bundled scripts, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursorrules`, `.cursor/rules`, `.windsurfrules`, Copilot instructions/prompts, Claude subagents/commands,
  `.claude/settings*.json`, hooks, `.mcp.json`, Cursor/VS Code/Gemini/Claude Desktop MCP configs,
  Codex `config.toml`, Claude plugin manifests; `--home` for user-level config; `--all-md`.
- 30 rules (PW001–PW030) across hidden content, prompt injection, dangerous commands, exfiltration,
  secrets, MCP configuration, permissions and skill metadata.
- Output formats: text (grouped, highlighted, hidden characters rendered visibly), JSON, SARIF 2.1.0, Markdown.
- `--fail-on`, `--min-severity`, `--ignore`, `--disable`, `--list-rules`, `--output`.
- Inline suppression (`promptwarden-ignore`, `promptwarden-ignore-file`) and `.promptwardenignore`.
- Composite GitHub Action with SARIF upload to GitHub code scanning.

[Unreleased]: https://github.com/paulochastinet/promptwarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/paulochastinet/promptwarden/releases/tag/v0.1.0
