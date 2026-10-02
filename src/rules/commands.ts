import type { FileContext, RawFinding } from '../context.js';
import { negatedInProse } from '../context.js';
import type { Severity } from '../types.js';

interface Pattern {
  ruleId: string;
  re: RegExp;
  message: string;
  severity?: Severity;
  /** Optional post-filter on the match. Return a severity to override, `false` to drop. */
  check?: (m: RegExpMatchArray, ctx: FileContext) => Severity | boolean | undefined;
}

const SHELLS = String.raw`(?:\/usr\/bin\/|\/bin\/|\/usr\/local\/bin\/|\/opt\/homebrew\/bin\/)?(?:ba|z|da|k|fi|c|tc|a)?sh\b`;
const INTERP = String.raw`(?:python[0-9.]*|perl|ruby|node|php|deno|bun)(?:\s+-)?\s*(?=$|[;&)|'"\x60\n])`;
const SUDO = String.raw`(?:sudo\s+(?:-[A-Za-z]+\s+)*)?(?:env\s+(?:\w+=\S*\s+)*)?`;
const FETCH = String.raw`\b(?:curl|wget|fetch|http|https|xh)\b`;

/**
 * Official installers that are widely documented. Still remote-code-execution, but reported as medium.
 */
const KNOWN_INSTALLERS =
  /(?:sh\.rustup\.rs|rustup\.rs|bun\.sh|deno\.land|deno\.com|astral\.sh|get\.pnpm\.io|raw\.githubusercontent\.com\/(?:Homebrew|nvm-sh|pyenv|ohmyzsh|tj\/n|creationix)\/|install\.python-poetry\.org|get\.docker\.com|claude\.ai\/install|opencode\.ai\/install|starship\.rs|ollama\.com\/install|fnm\.vercel\.app|get\.volta\.sh|mise\.run|pyenv\.run|pkgx\.sh|install\.determinate\.systems|nixos\.org|tailscale\.com\/install|cli\.github\.com|sdk\.cloud\.google\.com|cursor\.com\/install|foundry\.paradigm\.xyz|get\.helm\.sh|aka\.ms\/install-azd|chezmoi\.io|dot\.net\/v1\/dotnet-install|sh\.vector\.dev|deb\.nodesource\.com|rpm\.nodesource\.com|get\.sdkman\.io|install\.meteor\.com|railway\.(?:app|com)\/install|cli\.doppler\.com|vercel\.com\/install|fly\.io\/install|supabase\.com|get\.jetify\.com|raw\.githubusercontent\.com\/anthropics\/)/i;

const knownInstaller = (m: RegExpMatchArray): Severity | undefined => (KNOWN_INSTALLERS.test(m[0]) ? 'medium' : undefined);

const SECRET_VAR = String.raw`\$\{?[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|SESSION|COOKIE)[A-Za-z0-9_]*\}?`;
const CRED_FILE = String.raw`(?:\.env(?:\.[\w.-]+)?\b|\.ssh\/|\.aws\/credentials|\.netrc|\.git-credentials|\.npmrc|\.pypirc|\.docker\/config\.json|\.kube\/config)`;
const LOCAL_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|[\w-]+\.local|[\w-]+\.localhost)$/i;
/** Well-known APIs that legitimately receive tokens. */
const TRUSTED_API =
  /https?:\/\/(?:api\.github\.com|uploads\.github\.com|github\.com|gitlab\.com|api\.openai\.com|api\.anthropic\.com|[\w.-]*googleapis\.com|slack\.com\/api|api\.stripe\.com|api\.vercel\.com|api\.cloudflare\.com|registry\.npmjs\.org|api\.linear\.app|api\.notion\.com|api\.atlassian\.com|[\w-]+\.atlassian\.net|sentry\.io|api\.supabase\.(?:co|com)|[\w-]+\.supabase\.co|api\.netlify\.com|api\.heroku\.com|api\.digitalocean\.com|management\.azure\.com|login\.microsoftonline\.com|oauth2\.googleapis\.com|api\.telegram\.org(?!\/bot)|huggingface\.co|api\.mistral\.ai|api\.groq\.com|openrouter\.ai)/i;

export const PATTERNS: Pattern[] = [
  // ── PW009 remote code execution ──
  {
    ruleId: 'PW009',
    re: new RegExp(String.raw`\b(?:curl|wget)\b[^\n|;]*\|\s*${SUDO}(?:${SHELLS}|${INTERP})`, 'gi'),
    message: 'Remote content piped directly into a shell/interpreter',
    check: knownInstaller,
  },
  {
    ruleId: 'PW009',
    re: new RegExp(String.raw`(?:\b(?:ba|z)?sh|\bsource|(?:^|[\s;&(])\.)\s+<\(\s*(?:curl|wget)\b[^\n)]*\)`, 'gim'),
    message: 'Remote script executed via process substitution',
    check: knownInstaller,
  },
  {
    ruleId: 'PW009',
    re: /\b(?:(?:ba|z)?sh\s+-c|eval)\s+["']?\$\(\s*(?:curl|wget)\b[^\n]*/gi,
    message: 'Remote script executed via command substitution',
    check: knownInstaller,
  },
  {
    ruleId: 'PW009',
    re: /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|\(?new-object\s+(?:system\.)?net\.webclient\)?\.downloadstring)\b[^\n]*\|\s*(?:iex|invoke-expression)\b/gi,
    message: 'PowerShell download piped into Invoke-Expression',
    check: knownInstaller,
  },
  {
    ruleId: 'PW009',
    re: /\b(?:iex|invoke-expression)\s*[(\s]\s*\(?\s*(?:iwr|irm|invoke-webrequest|invoke-restmethod|\(?new-object\s+(?:system\.)?net\.webclient\)?\.downloadstring)\b[^\n]*/gi,
    message: 'PowerShell Invoke-Expression of downloaded content',
    check: knownInstaller,
  },
  {
    ruleId: 'PW009',
    re: /\b(?:exec|eval)\s*\(\s*(?:urllib\.request\.urlopen|requests\.get|urlopen)\s*\([^\n]*/g,
    message: 'Python exec/eval of content fetched from the network',
  },
  {
    ruleId: 'PW009',
    re: /\beval\s*\(\s*(?:await\s+)?\(?\s*await\s+fetch\s*\([^\n]*/g,
    message: 'JavaScript eval of content fetched from the network',
  },

  // ── PW010 encoded payload execution ──
  {
    ruleId: 'PW010',
    re: new RegExp(String.raw`\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*${SUDO}(?:${SHELLS}|${INTERP})`, 'gi'),
    message: 'Base64-decoded payload piped into a shell',
  },
  {
    ruleId: 'PW010',
    re: new RegExp(String.raw`\b(?:xxd\s+-r(?:\s+-p)?|openssl\s+(?:enc\s+)?-?(?:base64|a)\s+-d|rev)\b[^\n]*\|\s*${SUDO}(?:${SHELLS})`, 'gi'),
    message: 'Decoded/obfuscated payload piped into a shell',
  },
  {
    ruleId: 'PW010',
    re: /\beval\s+["']?\$\([^\n)]*\b(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r)/gi,
    message: 'eval of a decoded payload',
  },
  {
    ruleId: 'PW010',
    re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|__import__\(\s*['"]base64['"]\s*\))/g,
    message: 'Python exec/eval of a decoded payload',
  },
  {
    ruleId: 'PW010',
    re: /\b(?:eval|new\s+Function|setTimeout)\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\([^)]*['"](?:base64|hex)['"]|unescape\s*\(|String\.fromCharCode\s*\()/g,
    message: 'JavaScript eval of a decoded payload',
  },
  {
    ruleId: 'PW010',
    re: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/gi,
    message: 'PowerShell -EncodedCommand payload',
  },
  {
    ruleId: 'PW010',
    re: /FromBase64String[^\n]*\b(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\b[^\n]*FromBase64String/gi,
    message: 'PowerShell Invoke-Expression of a base64 payload',
  },

  // ── PW011 destructive ──
  {
    ruleId: 'PW011',
    re: /\brm\s+(?:-[A-Za-z]+\s+|--[a-z-]+\s+)*-(?:[A-Za-z]*[rR][A-Za-z]*[fF]|[A-Za-z]*[fF][A-Za-z]*[rR])[A-Za-z]*\s+(?:-[A-Za-z]+\s+|--[a-z-]+\s+)*["']?(?:\/\*?|~\/?\*?|\$HOME\/?\*?|\$\{HOME\}\/?\*?|\/Users\/?\*?|\/home\/?\*?|\/Users\/[^/\s"']+\/?\*?|\/home\/[^/\s"']+\/?\*?|C:\\\\?)["']?(?=\s|$|[;&|)])/gm,
    message: 'Recursive deletion of the root or home directory',
  },
  { ruleId: 'PW011', re: /\brm\b[^\n]*--no-preserve-root/g, message: 'rm with --no-preserve-root' },
  { ruleId: 'PW011', re: /\bmkfs(?:\.\w+)?\s+(?:-\S+\s+)*\/dev\/\w+/g, message: 'Formats a disk device' },
  { ruleId: 'PW011', re: /\bdd\s+[^\n]*\bof=\/dev\/(?:sd[a-z]|nvme\d|disk\d|hd[a-z]|xvd[a-z]|vd[a-z])/g, message: 'Overwrites a raw disk device' },
  { ruleId: 'PW011', re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/g, message: 'Fork bomb' },
  { ruleId: 'PW011', re: /\b(?:Remove-Item|rm|del)\s+[^\n]*-Recurse[^\n]*(?:C:\\(?:\s|$|["'])|\$env:USERPROFILE(?:\s|$|["'])|~(?:\s|$))/gi, message: 'Recursive deletion of a drive or user profile' },

  // ── PW012 reverse shell ──
  { ruleId: 'PW012', re: /\/dev\/(?:tcp|udp)\/[^\s/]+\/\d+/g, message: 'Bash /dev/tcp network redirection (reverse shell)' },
  { ruleId: 'PW012', re: /\b(?:nc|ncat|netcat)\b[^\n|;]*\s-(?:[A-Za-z]*e|c)\s+["']?(?:\/bin\/|\/usr\/bin\/)?(?:ba|z)?sh\b/g, message: 'netcat executing a shell' },
  { ruleId: 'PW012', re: /\b(?:ba)?sh\s+-i\s*[>&]+\s*\/dev\//g, message: 'Interactive shell redirected to a socket' },
  { ruleId: 'PW012', re: /\bsocat\b[^\n]*\bexec:[^\n]*(?:sh|bash|pty)/gi, message: 'socat executing a shell' },
  { ruleId: 'PW012', re: /\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat|telnet)\b/g, message: 'mkfifo + netcat reverse shell' },
  { ruleId: 'PW012', re: /socket\.socket\([^\n]*\bconnect\b[^\n]*(?:subprocess|pty\.spawn|os\.dup2)/g, message: 'Python socket connected to a spawned shell' },
  { ruleId: 'PW012', re: /\bpty\.spawn\(\s*["'](?:\/bin\/)?(?:ba)?sh["']\s*\)[^\n]*|os\.dup2\(\s*s\.fileno\(\)/g, message: 'Python PTY/socket shell' },
  { ruleId: 'PW012', re: /New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\s*\(/gi, message: 'PowerShell TCPClient (reverse shell pattern)' },

  // ── PW013 persistence ──
  { ruleId: 'PW013', re: /\|\s*crontab\s+(?:-u\s+\S+\s+)?-?(?=\s|$|[;&)])|\bcrontab\s+(?:-u\s+\S+\s+)?-\s*(?:$|[;&)<])|\bcrontab\s+(?:\/tmp\/|\$\(|<\()/gm, message: 'Installs a cron job' },
  { ruleId: 'PW013', re: /(?:>>?|\btee\s+(?:-a\s+)?|\bcp\s+\S+\s+|\bmv\s+\S+\s+)["']?\/(?:etc\/cron[\w.]*|var\/spool\/cron)\//g, message: 'Writes into the system cron directory' },
  { ruleId: 'PW013', re: /\blaunchctl\s+(?:load|bootstrap|submit|enable|kickstart)\b[^\n]*/g, message: 'Loads a launchd agent/daemon' },
  { ruleId: 'PW013', re: /(?:>>?|\btee\s+(?:-a\s+)?|\bcp\s+\S+\s+|\bmv\s+\S+\s+|\bln\s+-s\s+\S+\s+)["']?(?:~|\$HOME|\$\{HOME\})?\/?Library\/Launch(?:Agents|Daemons)\//g, message: 'Writes a LaunchAgent/LaunchDaemon' },
  { ruleId: 'PW013', re: /(?:>>?|\btee\s+-a\s+)\s*["']?(?:~|\$HOME|\$\{HOME\}|\/root|\/home\/[^/\s]+|\/Users\/[^/\s]+)?\/?\.ssh\/authorized_keys/g, message: 'Adds an SSH authorized key (backdoor)' },
  { ruleId: 'PW013', re: /\bschtasks(?:\.exe)?\s+\/create\b[^\n]*/gi, message: 'Creates a Windows scheduled task' },
  { ruleId: 'PW013', re: /\breg(?:\.exe)?\s+add\s+[^\n]*\\(?:Run|RunOnce)\b[^\n]*|New-ItemProperty[^\n]*CurrentVersion\\Run\b[^\n]*/gi, message: 'Adds a Windows Run registry key' },
  { ruleId: 'PW013', re: /\bsystemctl\s+--user\s+enable\b[^\n]*|(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?(?:~|\$HOME)\/\.config\/systemd\/user\//g, message: 'Installs a systemd user service', severity: 'medium' },
  {
    ruleId: 'PW013',
    re: /(?:>>|\btee\s+-a\s+)\s*["']?(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/\s]+|\/home\/[^/\s]+)\/\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile|config\/fish\/config\.fish)\b/g,
    message: 'Appends to a shell startup file',
    severity: 'medium',
  },
  { ruleId: 'PW013', re: /(?:>>?|\btee\s+(?:-a\s+)?|\bcp\s+\S+\s+|\bln\s+-sf?\s+\S+\s+)["']?(?:\S*\/)?\.git\/hooks\/[\w-]+/g, message: 'Installs a git hook', severity: 'medium' },

  // ── PW030 world-writable / tmp exec ──
  // needs a file argument after the mode, so prose like "avoid chmod 777)" or regex docs do not match
  { ruleId: 'PW030', re: /\bchmod[ \t]+(?:-R[ \t]+)?(?:0?777|a\+rwx|ugo\+rwx|o\+w)[ \t]+["']?[\w./~$][^\n]*/g, message: 'World-writable permissions' },
  {
    ruleId: 'PW030',
    re: /\bchmod\s+(?:\+x|[ua]\+x|0?[0-7][0-7][1357])\s+["']?\/(?:tmp|var\/tmp|dev\/shm)\/[^\s"';&]+/g,
    message: 'Makes a file in a temp directory executable',
  },

  // ── PW014 credential access ──
  {
    ruleId: 'PW014',
    re: /(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/\s]+|\/home\/[^/\s]+|\/root|%USERPROFILE%)\/\.ssh\/(?:id_[a-z0-9_]+|identity)\b(?![\w.]*\.pub)/gi,
    message: 'References a private SSH key',
    // Using a key (ssh -i, ssh-add, IdentityFile) or creating one is normal; reading/copying it is not.
    check: (m, ctx) => {
      const line = lineOf(ctx, m.index!);
      if (/\b(?:cat|cp|scp|rsync|tar|zip|base64|xxd|curl|wget|nc|open\(|readFile|read_text|fs\.read)/.test(line)) return undefined;
      return /\b(?:ssh-keygen|ssh-add|ssh-copy-id|ssh\s|IdentityFile|identity[-_]file|GIT_SSH_COMMAND|-i\s)/i.test(line) ? false : undefined;
    },
  },
  {
    ruleId: 'PW014',
    re: /\b(?:cat|cp|tar|zip|scp|base64|rsync|xxd|gzip|7z|less|more|head|tail|find|ls)\b[^\n|;]*?(?:~|\$HOME|\$\{HOME\})\/\.ssh(?:\/\*?)?(?=[\s"'`;|)]|$)/gm,
    message: 'Reads or archives the ~/.ssh directory',
  },
  { ruleId: 'PW014', re: /\.aws\/credentials\b/g, message: 'References AWS credentials file' },
  { ruleId: 'PW014', re: /\.config\/gcloud\/(?:credentials\.db|application_default_credentials\.json|access_tokens\.db|legacy_credentials)/g, message: 'References Google Cloud credentials' },
  { ruleId: 'PW014', re: /\.azure\/(?:accessTokens\.json|msal_token_cache[\w.]*)/g, message: 'References Azure tokens' },
  { ruleId: 'PW014', re: /(?:~|\$HOME|\$\{HOME\})\/\.(?:netrc|git-credentials)\b/g, message: 'References stored git/HTTP credentials' },
  {
    ruleId: 'PW014',
    re: /\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain|export)\b[^\n]*/g,
    message: 'Reads the macOS keychain',
    // Fetching one named item (-s service -w) is a common way for a script to read its own token: medium.
    check: (m) => (/dump-keychain|\bexport\b|Safe Storage|login\.keychain|-ga\b|-g\b/.test(m[0]) ? undefined : /-s\s+\S+/.test(m[0]) ? 'medium' : undefined),
  },
  { ruleId: 'PW014', re: /\b(?:mimikatz|lazagne|sekurlsa|hashdump)\b/gi, message: 'Credential dumping tool' },
  {
    ruleId: 'PW014',
    re: /(?:Google\/Chrome|Chromium|BraveSoftware\/Brave-Browser|Microsoft\/Edge|Microsoft Edge|google-chrome|Opera Software|Vivaldi|Arc\/User Data)\/[^\n"']*?(?:Cookies|Login Data|Web Data|Local State)\b/g,
    message: 'Reads browser cookie/password databases',
  },
  { ruleId: 'PW014', re: /Firefox\/Profiles\/[^\n"']*?(?:cookies\.sqlite|logins\.json|key[34]\.db)|\b(?:cookies\.sqlite|key4\.db)\b/g, message: 'Reads Firefox cookie/password stores' },
  { ruleId: 'PW014', re: /\bwallet\.dat\b|Exodus\/exodus\.wallet|Electrum\/wallets|nkbihfbeogaeaoehlefnkodbefgpgknn|Library\/Application Support\/(?:Exodus|atomic|Ledger Live)\b/g, message: 'Accesses cryptocurrency wallet data' },

  // ── PW015 exfil endpoints ──
  {
    ruleId: 'PW015',
    re: /\b(?:[a-z0-9-]+\.)*(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|ngrok\.io|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|localhost\.run|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|oastify\.com|canarytokens\.com|requestcatcher\.com|beeceptor\.com|hookbin\.com|postb\.in|pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|transfer\.sh|file\.io|0x0\.st|termbin\.com|dnslog\.cn|ceye\.io|requestrepo\.com)\b[^\s"'`)\]]*/gi,
    message: 'Request-capture / tunnel / paste endpoint',
  },
  { ruleId: 'PW015', re: /\bdiscord(?:app)?\.com\/api\/webhooks\/[^\s"'`)]*/gi, message: 'Discord webhook endpoint' },
  { ruleId: 'PW015', re: /\bapi\.telegram\.org\/bot[^\s"'`)]*/gi, message: 'Telegram bot API endpoint' },

  // ── PW016 secret exfiltration ──
  { ruleId: 'PW016', re: /\b(?:env|printenv|set|export\s+-p|Get-ChildItem\s+env:|gci\s+env:)\s*\|[^\n]*\b(?:curl|wget|nc|ncat|netcat|http|https|xh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*/gi, message: 'Environment variables piped to a network command' },
  {
    ruleId: 'PW016',
    re: new RegExp(String.raw`${FETCH}[^\n]*(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file|--post-file|--body-file)\s*[=\s]?["']?[\w-]*=?@["']?(?:~\/|\$HOME\/|\$\{HOME\}\/|\.\/)?\S*${CRED_FILE}[^\n]*`, 'g'),
    message: 'Uploads a credential file',
  },
  {
    ruleId: 'PW016',
    re: new RegExp(String.raw`\b(?:cat|base64|gzip|tar)\b[^\n|]*${CRED_FILE}[^\n|]*\|[^\n]*\b(?:curl|wget|nc|ncat|netcat|xh)\b[^\n]*`, 'g'),
    message: 'Credential file piped to a network command',
  },
  {
    ruleId: 'PW016',
    re: new RegExp(String.raw`${FETCH}[^\n]*\$\(\s*(?:cat|base64)\s+[^)]*${CRED_FILE}[^\n]*`, 'g'),
    message: 'Credential file content embedded in a network request',
  },
  {
    ruleId: 'PW016',
    re: new RegExp(String.raw`\b(?:curl|wget|xh)\b[^\n]*(?:\s-d\s*|--data(?:-\w+)?[\s=]|\s-F\s*|--form[\s=]|--post-data[\s=]|\?[^\s"']*=)[^\n]*${SECRET_VAR}[^\n]*`, 'g'),
    message: 'Secret-named variable sent in a request body/query',
    severity: 'high',
    check: (m) => (TRUSTED_API.test(m[0]) ? false : undefined),
  },
  {
    ruleId: 'PW016',
    re: /\brequests\.(?:post|put|patch|get)\s*\([^\n]*(?:os\.environ\b(?!\s*[.[(])|dict\(\s*os\.environ\s*\))[^\n]*|\burllib[^\n]*urlopen\([^\n]*os\.environ\b(?!\s*[.[(])[^\n]*/g,
    message: 'Python sends the whole environment over the network',
  },
  {
    ruleId: 'PW016',
    re: /\b(?:fetch|axios(?:\.(?:post|put))?|got(?:\.post)?|https?\.request|request\.post)\s*\([^\n]*\bprocess\.env\b(?!\s*[.[])[^\n]*/g,
    message: 'JavaScript sends the whole environment over the network',
  },
  {
    ruleId: 'PW016',
    re: /JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(?:dict\()?\s*os\.environ(?:\.copy\(\))?\s*\)?\s*\)/g,
    message: 'Serializes the entire environment (common exfiltration step)',
    severity: 'high',
  },

  // ── PW024 permission bypass (text mentions) ──
  {
    ruleId: 'PW024',
    re: /--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|--permission-mode[ =]["']?bypassPermissions\b|\bgemini\b[^\n]*\s--yolo\b|\bcodex\b[^\n]*\s--full-auto\b[^\n]*danger|--sandbox[ =]["']?danger-full-access\b/g,
    message: 'Runs an agent with permission prompts / sandbox disabled',
    severity: 'medium',
  },
];

/** Hint used by PW004 (hidden comments) */
export const COMMAND_HINT =
  /\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n]*(?:\||https?:\/\/)|\brm\s+-rf\b|\/dev\/tcp\/|\bbase64\s+-d\b|\b(?:cat|read)\s+[^\n]*(?:\.env|\.ssh|\.aws)|webhook\.site|ngrok|\beval\b|\bexec\(/i;

/** PW009–PW016, PW024 (text), PW030 */
export function detectCommands(ctx: FileContext): RawFinding[] {
  const out: RawFinding[] = [];
  const s = ctx.content;
  for (const p of PATTERNS) {
    if (p.ruleId === 'PW024' && (ctx.kind === 'claude-settings' || ctx.kind === 'codex-config')) continue;
    p.re.lastIndex = 0;
    for (const m of s.matchAll(p.re)) {
      const start = m.index!;
      const text = m[0];
      const end = start + text.length;
      if (negatedInProse(ctx, start)) continue;
      // Comments in scripts are not executed.
      if (ctx.kind === 'script' && /^\s*(?:\/\/|#(?!!)|\*|\/\*|--\s|REM\s|<#|"""|''')/i.test(lineOf(ctx, start))) continue;
      let severity = p.severity;
      if (p.check) {
        const r = p.check(m, ctx);
        if (r === false) continue;
        if (typeof r === 'string') severity = r;
      }
      if (p.ruleId === 'PW015' && isLocalUrlContext(text)) continue;
      out.push({ ruleId: p.ruleId, start, end, message: text.trim().length <= 60 ? `${p.message}: ${text.trim()}` : p.message, severity });
    }
  }
  return collapseMentions(dedupeOverlaps(out));
}

/** Text mentions of permission bypass flags are reported once per file. */
function collapseMentions(findings: RawFinding[]): RawFinding[] {
  const bypass = findings.filter((f) => f.ruleId === 'PW024');
  if (bypass.length <= 1) return findings;
  const first = bypass[0]!;
  first.message += ` (+${bypass.length - 1} more mention${bypass.length > 2 ? 's' : ''} in this file)`;
  return findings.filter((f) => f.ruleId !== 'PW024' || f === first);
}

function lineOf(ctx: FileContext, offset: number): string {
  return ctx.lines.lineText(ctx.lines.position(offset).line);
}

function isLocalUrlContext(text: string): boolean {
  const host = /^(?:https?:\/\/)?([^/:\s]+)/i.exec(text)?.[1];
  return host ? LOCAL_HOST.test(host) : false;
}

/** Keep one finding per rule per overlapping range (patterns of the same rule can overlap). */
function dedupeOverlaps(findings: RawFinding[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const f of findings) {
    const dup = out.find((o) => o.ruleId === f.ruleId && f.start < o.end && f.end > o.start);
    if (!dup) out.push(f);
  }
  return out;
}

export { LOCAL_HOST, KNOWN_INSTALLERS };
