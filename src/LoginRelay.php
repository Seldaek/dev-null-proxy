<?php declare(strict_types=1);

namespace DevNullProxy;

/**
 * GitHub only redirects back to the real upstream host, so the OAuth callback arrives with the browser's
 * upstream cookies instead of the proxy-side session that holds the OAuth state. This keeps track of which
 * proxy session started which login, so the callback can be replayed with it.
 */
final class LoginRelay
{
    public const PATH = '/__dev-null-proxy';
    private const STATE_TTL = 900;
    private const TOKEN_TTL = 120;
    // Laravel's remember-me cookie lasts 400 days
    private const IMPORTED_COOKIE_TTL = 34560000;

    /** @var array<string, array{cookies: array<string, string>, origin: string, expires: int}> */
    private array $pending = [];
    /** @var array<string, array{setCookies: list<string>, location: string, expires: int}> */
    private array $tokens = [];

    public function rememberLogin(string $state, array $cookies, string $origin): void
    {
        $this->prune();
        $this->pending[$state] = ['cookies' => $cookies, 'origin' => $origin, 'expires' => time() + self::STATE_TTL];
    }

    /**
     * @return array{cookies: array<string, string>, origin: string}|null
     */
    public function takeLogin(string $state): ?array
    {
        $this->prune();
        $login = $this->pending[$state] ?? null;
        unset($this->pending[$state]);

        return $login;
    }

    /**
     * @param list<string> $setCookies
     */
    public function issueToken(array $setCookies, string $location): string
    {
        $token = bin2hex(random_bytes(16));
        $this->tokens[$token] = ['setCookies' => $setCookies, 'location' => $location, 'expires' => time() + self::TOKEN_TTL];

        return $token;
    }

    /**
     * @return array{setCookies: list<string>, location: string}|null
     */
    public function redeemToken(string $token): ?array
    {
        $this->prune();
        $entry = $this->tokens[$token] ?? null;
        unset($this->tokens[$token]);

        return $entry;
    }

    /**
     * @return array<string, string>
     */
    public static function parseCookieHeader(string $header): array
    {
        $cookies = [];
        foreach (explode(';', $header) as $pair) {
            if (str_contains($pair, '=')) {
                [$name, $value] = explode('=', $pair, 2);
                $cookies[trim($name)] = trim($value);
            }
        }

        return $cookies;
    }

    /**
     * @param list<string> $setCookies
     * @param array<string, string> $cookies
     * @return array<string, string>
     */
    public static function applySetCookies(array $cookies, array $setCookies): array
    {
        foreach ($setCookies as $setCookie) {
            $pair = explode(';', $setCookie, 2)[0];
            if (str_contains($pair, '=')) {
                [$name, $value] = explode('=', $pair, 2);
                $cookies[trim($name)] = trim($value);
            }
        }

        return $cookies;
    }

    /**
     * Accepts what people paste from devtools: "name=value; name2=value2", one per line, or "name<tab>value".
     *
     * @return list<string> Set-Cookie headers
     */
    public static function importCookies(string $input): array
    {
        $headers = [];
        $input = preg_replace('{^\s*cookie:\s*}i', '', $input);
        foreach (preg_split('{[;\r\n]+}', $input) as $chunk) {
            $chunk = trim($chunk);
            if (!preg_match('{^([A-Za-z0-9_.\-]+)(?:\s*=\s*|\s+)([^\s;,]+)}', $chunk, $m)) {
                continue;
            }
            $headers[] = sprintf('%s=%s; Path=/; Max-Age=%d; Secure; HttpOnly; SameSite=Lax', $m[1], $m[2], self::IMPORTED_COOKIE_TTL);
        }

        return $headers;
    }

    public function renderLoginPage(string $upstreamHost, bool $overridden, ?int $port, ?string $error = null): string
    {
        $h = static fn (string $s) => htmlspecialchars($s, ENT_QUOTES);
        $host = '<code>'.$h($upstreamHost).'</code>';
        // GitHub always returns to https://<upstream>/, i.e. port 443, so that's where the proxy must listen
        $portFix = '<p>Restart it without <code>--port</code>.'.(PHP_OS_FAMILY === 'Linux' ? ' If binding 443 is refused, allow low ports once with:</p><pre>sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80</pre>' : '</p>');
        $status = match (true) {
            $overridden && $port === null => '<p class="ok">'.$host.' points at this proxy, so you will come back here signed in.</p>',
            $overridden => '<div class="callout"><strong>The proxy runs on port '.$port.', but GitHub always sends you back to port 443.</strong>'
                .'<p>'.$host.' already points at this machine, but nothing answers on 443, so the return from GitHub will fail.</p>'.$portFix.'</div>',
            default => '<div class="callout"><strong>GitHub will send you back to the real '.$host.', not to this proxy.</strong>'
                .'<p>You would end up signed in there, not here. To come back here signed in, add this to your hosts file:</p><pre>127.0.0.1 '.$h($upstreamHost).'</pre>'
                .($port !== null ? '<p>The proxy also has to run on port 443, it is on '.$port.' now.</p>'.$portFix : '').'</div>',
        };
        $errorHtml = $error !== null ? '<p class="error">'.$h($error).'</p>' : '';

        return <<<HTML
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sign in · dev-null-proxy</title>
            <style>
                :root { color-scheme: light dark; --bg: #f6f7f8; --fg: #111112; --muted: #666; --box: #fff; --line: #ddd; }
                @media (prefers-color-scheme: dark) { :root { --bg: #111112; --fg: #eee; --muted: #999; --box: #1b1b1d; --line: #333; } }
                body { background: var(--bg); color: var(--fg); font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0; padding: 32px 16px; }
                main { max-width: 640px; margin: 0 auto; }
                h1 { font-size: 20px; } h2 { font-size: 16px; margin-top: 32px; }
                pre, textarea { background: var(--box); border: 1px solid var(--line); border-radius: 6px; padding: 10px; width: 100%; box-sizing: border-box; color: inherit; font: inherit; }
                pre { overflow-x: auto; }
                .ok { color: #2a8; }
                .callout { border: 1px solid #c80; border-left-width: 4px; border-radius: 6px; padding: 12px 14px; margin: 16px 0; background: color-mix(in srgb, #c80 10%, transparent); }
                .callout strong { display: block; }
                .callout p { margin: 8px 0 0; }
                a.button { display: inline-block; text-decoration: none; }
                button, a.button { margin-top: 10px; padding: 8px 16px; font: inherit; border-radius: 6px; border: 1px solid var(--line); background: var(--fg); color: var(--bg); cursor: pointer; }
                .error { color: #d33; }
                li { margin-bottom: 4px; }
                code { font-size: 14px; }
            </style>
            </head>
            <body><main>
            <h1>Sign in to {$h($upstreamHost)} through the proxy</h1>
            {$errorHtml}
            {$status}
            <a class="button" href="{$h(self::PATH)}/github">Sign in with GitHub</a>
            <h2>Or import your session</h2>
            <ol>
                <li>Sign in on <a href="https://{$h($upstreamHost)}/">https://{$h($upstreamHost)}</a>.</li>
                <li>Open devtools → Application (Storage in Firefox) → Cookies → https://{$h($upstreamHost)}.</li>
                <li>Copy the name and value of the <code>remember_web_…</code> cookie and paste it below as <code>name=value</code>.</li>
            </ol>
            <form method="post">
                <textarea name="cookies" rows="4" placeholder="remember_web_59ba36…=eyJpdiI6…" required></textarea>
                <button type="submit">Import</button>
            </form>
            </main></body>
            </html>
            HTML;
    }

    private function prune(): void
    {
        $now = time();
        $this->pending = array_filter($this->pending, static fn (array $p) => $p['expires'] > $now);
        $this->tokens = array_filter($this->tokens, static fn (array $t) => $t['expires'] > $now);
    }
}
