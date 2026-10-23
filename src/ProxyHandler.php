<?php declare(strict_types=1);

namespace DevNullProxy;

use Amp\Http\Client\BufferedContent;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request as ClientRequest;
use Amp\Http\Client\Response as ClientResponse;
use Amp\Http\Client\StreamedContent;
use Amp\Http\HttpStatus;
use Amp\Http\Server\Request;
use Amp\Http\Server\RequestHandler;
use Amp\Http\Server\Response;
use Psr\Log\LoggerInterface;

final class ProxyHandler implements RequestHandler
{
    private const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'host', 'content-length'];
    // body types where absolute upstream URLs get rewritten to the local origin
    private const REWRITE_TYPES = ['text/html', 'application/json', 'text/css', 'application/javascript', 'text/javascript', 'application/xml', 'text/xml', 'application/manifest+json'];
    // uploads (photos in commits and replies) and downloads alike
    private const MAX_BODY_SIZE = 512 * 1024 * 1024;
    // request bodies that may carry links typed or pasted by the user
    private const OUTGOING_REWRITE_TYPES = ['application/json', 'text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data'];
    private const GITHUB_AUTHORIZE = 'https://github.com/login/oauth/authorize';

    private readonly HttpClient $client;
    private readonly string $upstream;
    private readonly string $upstreamHost;
    private readonly string $prefix;
    private readonly LoginRelay $relay;

    public function __construct(string $upstream, string $prefix, private readonly UpstreamDnsResolver $dns, private readonly LoggerInterface $logger)
    {
        $this->upstream = rtrim($upstream, '/');
        $this->upstreamHost = strtolower((string) parse_url($this->upstream, PHP_URL_HOST));
        $this->prefix = '/'.trim($prefix, '/');
        $this->relay = new LoginRelay();
        $this->client = (new HttpClientBuilder())
            ->followRedirects(0)
            ->retry(0)
            ->build();
    }

    public function handleRequest(Request $request): Response
    {
        if (strtolower($request->getUri()->getHost()) === $this->upstreamHost) {
            return $this->handleUpstreamHost($request);
        }

        $uri = $request->getUri();
        $origin = $uri->getScheme().'://'.self::authority($request);

        $path = $uri->getPath();
        if ($path === LoginRelay::PATH || str_starts_with($path, LoginRelay::PATH.'/')) {
            return $this->handleProxyPage($request, $origin);
        }

        if ($path === '/sw.js' || $path === $this->localRoot().'/sw.js') {
            return $this->selfRemovingServiceWorker();
        }

        // /null maps to the upstream root; everything else passes through since the site links root-relative
        if ($this->prefix !== '/' && ($path === $this->prefix || str_starts_with($path, $this->prefix.'/'))) {
            $path = substr($path, strlen($this->prefix)) ?: '/';
        }
        $target = $this->upstream.$path.($uri->getQuery() !== '' ? '?'.$uri->getQuery() : '');

        $upstreamResponse = $this->forward(
            $request,
            $target,
            ['accept-encoding' => null],
            fn (string $v) => $this->toUpstream($v, $origin),
            fn (string $body, string $contentType) => $this->rewriteOutgoingBody($body, $contentType, $origin),
        );
        if ($upstreamResponse instanceof Response) {
            return $upstreamResponse;
        }

        if (null !== ($loginRedirect = $this->interceptGitHubRedirect($request, $upstreamResponse, $origin, true))) {
            return $loginRedirect;
        }

        $headers = [];
        foreach ($upstreamResponse->getHeaders() as $name => $values) {
            if (in_array($name, self::HOP_BY_HOP, true) || $name === 'strict-transport-security' || $name === 'alt-svc') {
                continue;
            }
            $headers[$name] = match ($name) {
                'location', 'x-inertia-location' => array_map(fn (string $v) => $this->toLocalNavigation($v, $origin), $values),
                'link', 'refresh', 'content-location' => array_map(fn (string $v) => $this->toLocal($v, $origin), $values),
                'set-cookie' => array_map($this->stripCookieDomain(...), $values),
                default => $values,
            };
        }

        $contentType = strtolower(trim(explode(';', $upstreamResponse->getHeader('content-type') ?? '')[0]));
        if (in_array($contentType, self::REWRITE_TYPES, true)) {
            $body = $upstreamResponse->getBody()->buffer();
            if ($contentType === 'text/html') {
                $body = $this->prefixInertiaPageInHtml($body);
            } elseif ($upstreamResponse->hasHeader('x-inertia')) {
                $body = $this->prefixInertiaPage($body);
            }
            $body = $this->toLocal($body, $origin);
            if ($contentType === 'text/html') {
                // after toLocal(), which would point the script's upstream URL back at the proxy
                $body = $this->injectClipboardFix($body, $origin);
            }
        } else {
            $body = $upstreamResponse->getBody();
            if (null !== ($length = $upstreamResponse->getHeader('content-length')) && !$upstreamResponse->hasHeader('content-encoding')) {
                $headers['content-length'] = $length;
            }
        }

        return new Response($upstreamResponse->getStatus(), $headers, $body);
    }

    /**
     * Requests for the upstream host itself only arrive here when the hosts file points it at the proxy.
     * They pass through untouched, except for the GitHub callback of a login started on the proxy.
     */
    private function handleUpstreamHost(Request $request): Response
    {
        $uri = $request->getUri();
        $target = $this->upstream.$uri->getPath().($uri->getQuery() !== '' ? '?'.$uri->getQuery() : '');

        if ($uri->getPath() === '/sw.js') {
            return $this->selfRemovingServiceWorker();
        }

        parse_str($uri->getQuery(), $query);
        $login = is_string($query['state'] ?? null) ? $this->relay->takeLogin($query['state']) : null;
        if ($login === null) {
            $upstreamResponse = $this->forward($request, $target);
            if ($upstreamResponse instanceof Response) {
                return $upstreamResponse;
            }

            $headers = array_diff_key($upstreamResponse->getHeaders(), array_flip(self::HOP_BY_HOP));
            if (null !== ($length = $upstreamResponse->getHeader('content-length'))) {
                $headers['content-length'] = $length;
            }

            return new Response($upstreamResponse->getStatus(), $headers, $upstreamResponse->getBody());
        }

        // replay the callback with the proxy-side session that holds the OAuth state
        $cookieHeader = implode('; ', array_map(static fn ($k, $v) => $k.'='.$v, array_keys($login['cookies']), $login['cookies']));
        $upstreamResponse = $this->forward($request, $target, ['cookie' => [$cookieHeader], 'accept-encoding' => null]);
        if ($upstreamResponse instanceof Response) {
            return $upstreamResponse;
        }
        $upstreamResponse->getBody()->buffer();

        $location = $this->toLocalNavigation($upstreamResponse->getHeader('location') ?? '/', $login['origin']);
        if (str_starts_with($location, '/')) {
            $location = $login['origin'].$location;
        }
        $token = $this->relay->issueToken($upstreamResponse->getHeaderArray('set-cookie'), $location);
        $this->logger->notice('Relayed GitHub sign in back to '.$login['origin']);

        return new Response(HttpStatus::SEE_OTHER, ['location' => $login['origin'].LoginRelay::PATH.'/session?token='.$token, 'cache-control' => 'no-store']);
    }

    /**
     * Login redirects to GitHub come back to the real upstream host: remember the session that started
     * them, and unless $explain is off, show the sign in page when that callback can't reach the proxy.
     */
    private function interceptGitHubRedirect(Request $request, ClientResponse $upstreamResponse, string $origin, bool $explain): ?Response
    {
        $location = $upstreamResponse->getHeader('location') ?? $upstreamResponse->getHeader('x-inertia-location') ?? '';
        if (!str_starts_with($location, self::GITHUB_AUTHORIZE.'?')) {
            return null;
        }
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        if (!is_string($query['state'] ?? null) || strtolower((string) parse_url((string) ($query['redirect_uri'] ?? ''), PHP_URL_HOST)) !== $this->upstreamHost) {
            return null;
        }

        $upstreamResponse->getBody()->buffer();
        // Inertia visits can't follow cross-origin redirects, they need a 409 to do a full page load
        $redirect = static fn (string $url, array $headers = []) => $request->hasHeader('x-inertia')
            ? new Response(HttpStatus::CONFLICT, ['x-inertia-location' => $url, 'cache-control' => 'no-store'] + $headers)
            : new Response(HttpStatus::FOUND, ['location' => $url, 'cache-control' => 'no-store'] + $headers);

        if ($explain && (!$this->dns->isOverridden() || self::port($request) !== null)) {
            return $redirect($origin.LoginRelay::PATH.'/login');
        }

        $cookies = LoginRelay::applySetCookies(
            LoginRelay::parseCookieHeader(implode('; ', $request->getHeaderArray('cookie'))),
            $upstreamResponse->getHeaderArray('set-cookie'),
        );
        $this->relay->rememberLogin($query['state'], $cookies, $origin);

        // the response may have started the session, so pass its cookies on along with the redirect
        $headers = [];
        if ($upstreamResponse->hasHeader('set-cookie')) {
            $headers['set-cookie'] = array_map($this->stripCookieDomain(...), $upstreamResponse->getHeaderArray('set-cookie'));
        }

        return $redirect($location, $headers);
    }

    /**
     * Host as the client sent it: amphp fills in the listening port when it has none, which behind
     * nginx would turn https://dev into https://dev:8443.
     */
    private static function authority(Request $request): string
    {
        $host = $request->getHeader('host');

        return strtolower($host !== null && $host !== '' ? $host : $request->getUri()->getAuthority());
    }

    private static function port(Request $request): ?int
    {
        return preg_match('{:(\d+)$}', self::authority($request), $m) && $m[1] !== '443' ? (int) $m[1] : null;
    }

    /**
     * The site's worker turns any failed navigation into its offline page: on dev-null.sh it can't reach
     * loopback (GitHub callback included), and on the proxy it hides real errors like a bad certificate.
     */
    private function selfRemovingServiceWorker(): Response
    {
        return new Response(HttpStatus::OK, ['content-type' => 'text/javascript', 'cache-control' => 'no-store'], <<<'JS'
            self.addEventListener('install', () => self.skipWaiting());
            self.addEventListener('activate', (event) => event.waitUntil(self.registration.unregister()));

            JS);
    }

    private function handleProxyPage(Request $request, string $origin): Response
    {
        $path = substr($request->getUri()->getPath(), strlen(LoginRelay::PATH));
        $html = ['content-type' => 'text/html; charset=utf-8', 'cache-control' => 'no-store'];

        if ($path === '/session') {
            parse_str($request->getUri()->getQuery(), $query);
            $entry = is_string($query['token'] ?? null) ? $this->relay->redeemToken($query['token']) : null;
            if ($entry === null) {
                return new Response(HttpStatus::SEE_OTHER, ['location' => $origin.$this->localRoot().'/']);
            }

            return new Response(HttpStatus::SEE_OTHER, [
                'location' => $entry['location'],
                'set-cookie' => array_map($this->stripCookieDomain(...), $entry['setCookies']),
                'cache-control' => 'no-store',
            ]);
        }

        // the sign in page's GitHub button: start the upstream login without detouring to that page again
        if ($path === '/github') {
            $upstreamResponse = $this->forward($request, $this->upstream.'/login', ['accept-encoding' => null], fn (string $v) => $this->toUpstream($v, $origin));
            if ($upstreamResponse instanceof Response) {
                return $upstreamResponse;
            }

            return $this->interceptGitHubRedirect($request, $upstreamResponse, $origin, false)
                ?? new Response(HttpStatus::SEE_OTHER, ['location' => $origin.$this->localRoot().'/']);
        }

        if ($path !== '/login') {
            return new Response(HttpStatus::NOT_FOUND, ['content-type' => 'text/plain'], 'Not found');
        }

        $render = fn (?string $error = null) => $this->relay->renderLoginPage($this->upstreamHost, $this->dns->isOverridden(), self::port($request), $error);
        if ($request->getMethod() !== 'POST') {
            return new Response(HttpStatus::OK, $html, $render());
        }

        // only accept the form from our own page, so other sites can't plant a session
        if ($request->getHeader('origin') !== $origin) {
            return new Response(HttpStatus::FORBIDDEN, $html, $render('Cross-origin request refused.'));
        }
        parse_str($request->getBody()->buffer(limit: 64 * 1024), $form);
        $setCookies = LoginRelay::importCookies(is_string($form['cookies'] ?? null) ? $form['cookies'] : '');
        if ($setCookies === []) {
            return new Response(HttpStatus::UNPROCESSABLE_ENTITY, $html, $render('No cookie found, paste it as name=value.'));
        }

        return new Response(HttpStatus::SEE_OTHER, ['location' => $origin.$this->localRoot().'/', 'set-cookie' => $setCookies, 'cache-control' => 'no-store']);
    }

    /**
     * @param array<string, list<string>|null> $overrides headers to replace, or drop when null
     * @param (\Closure(string): string)|null $toUpstream rewrites origin/referer
     * @param (\Closure(string, string): string)|null $rewriteBody rewrites text request bodies, given the content type
     */
    private function forward(Request $request, string $target, array $overrides = [], ?\Closure $toUpstream = null, ?\Closure $rewriteBody = null): ClientResponse|Response
    {
        $upstreamRequest = new ClientRequest($target, $request->getMethod());
        $upstreamRequest->setTransferTimeout(300);
        $upstreamRequest->setInactivityTimeout(60);
        $upstreamRequest->setBodySizeLimit(self::MAX_BODY_SIZE);
        foreach ($request->getHeaders() as $name => $values) {
            if (in_array($name, self::HOP_BY_HOP, true) || str_starts_with($name, ':') || array_key_exists($name, $overrides)) {
                continue;
            }
            if ($toUpstream !== null && ($name === 'origin' || $name === 'referer')) {
                $values = array_map($toUpstream, $values);
            }
            $upstreamRequest->setHeader($name, $values);
        }
        foreach (array_filter($overrides) as $name => $values) {
            $upstreamRequest->setHeader($name, $values);
        }

        if (!in_array($request->getMethod(), ['GET', 'HEAD'], true)) {
            // amphp's server caps request bodies at 128 KB by default
            $request->getBody()->increaseSizeLimit(self::MAX_BODY_SIZE);
            $contentType = (string) $request->getHeader('content-type');
            if ($rewriteBody !== null && in_array(strtolower(trim(explode(';', $contentType)[0])), self::OUTGOING_REWRITE_TYPES, true)) {
                $upstreamRequest->setBody(BufferedContent::fromString($rewriteBody($request->getBody()->buffer(), $contentType), $contentType));
            } else {
                $length = $request->getHeader('content-length');
                $upstreamRequest->setBody(StreamedContent::fromStream(
                    $request->getBody(),
                    $length !== null ? (int) $length : null,
                    $contentType !== '' ? $contentType : null,
                ));
            }
        }

        try {
            $response = $this->client->request($upstreamRequest);
        } catch (HttpException $e) {
            $this->logger->error(sprintf('%s %s -> upstream error: %s', $request->getMethod(), $target, $e->getMessage()));

            return new Response(HttpStatus::BAD_GATEWAY, ['content-type' => 'text/plain'], 'dev-null-proxy: upstream request failed: '.$e->getMessage());
        }
        $this->logger->info(sprintf('%s %s -> %d', $request->getMethod(), $target, $response->getStatus()));

        return $response;
    }

    private function toLocal(string $value, string $origin): string
    {
        $escaped = str_replace('/', '\/', $this->upstream);

        // longest first: bare-upstream URLs (e.g. canonical "https://dev-null.sh") become the prefixed homepage
        return str_replace(
            [$this->upstream.'/', $escaped.'\/', $this->upstream, $escaped],
            [$origin.'/', str_replace('/', '\/', $origin).'\/', $origin.$this->localRoot(), str_replace('/', '\/', $origin.$this->localRoot())],
            $value,
        );
    }

    /**
     * Redirect targets keep the browser under the prefix, so reloading lands on the same page.
     */
    private function toLocalNavigation(string $value, string $origin): string
    {
        if (str_starts_with($value, $this->upstream.'/') || $value === $this->upstream) {
            return $origin.$this->withPrefix(substr($value, strlen($this->upstream)) ?: '/');
        }
        if (str_starts_with($value, '/') && !str_starts_with($value, '//')) {
            return $this->withPrefix($value);
        }

        return $value;
    }

    /**
     * Plain string search: a regex hits PCRE's backtrack limit once signed-in pages pass 1 MB.
     */
    private function prefixInertiaPageInHtml(string $html): string
    {
        $open = '<script data-page="app" type="application/json">';
        if (false === ($start = strpos($html, $open)) || false === ($end = strpos($html, '</script>', $start += strlen($open)))) {
            return $html;
        }

        return substr_replace($html, $this->prefixInertiaPage(substr($html, $start, $end - $start), JSON_HEX_TAG | JSON_HEX_AMP), $start, $end - $start);
    }

    /**
     * Inertia replaces the address bar with the page object's url on load, which would drop the prefix.
     */
    private function prefixInertiaPage(string $json, int $flags = 0): string
    {
        try {
            $page = json_decode($json, false, 4096, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException $e) {
            $this->logger->warning('Could not add the prefix to an Inertia page: '.$e->getMessage());

            return $json;
        }
        if (!$page instanceof \stdClass || !isset($page->url, $page->component) || !is_string($page->url)) {
            return $json;
        }
        $page->url = $this->withPrefix($page->url);

        return json_encode($page, $flags | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION) ?: $json;
    }

    private function withPrefix(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH) ?? '/';
        if ($this->prefix === '/' || $path === $this->prefix || str_starts_with($path, $this->prefix.'/')) {
            return $url;
        }

        return $this->prefix.($path === '/' ? substr($url, 1) : $url);
    }

    /**
     * Links copied on the proxy point at it, so posted as they are they'd be dead for everyone else.
     */
    private function linksToUpstream(string $text, string $origin): string
    {
        // https://dev and https://dev/null (also at the end of a sentence), but not https://dev-null.sh or https://devtools
        $pattern = '{'.preg_quote($origin).'(?:'.preg_quote($this->localRoot()).'(?![\w-])|(?![\w.:-]))}';

        return preg_replace($pattern, $this->upstream, $text) ?? $text;
    }

    private function rewriteOutgoingBody(string $body, string $contentType, string $origin): string
    {
        $type = strtolower(trim(explode(';', $contentType)[0]));
        if ($type === 'application/x-www-form-urlencoded') {
            return implode('&', array_map(function (string $pair) use ($origin) {
                [$name, $value] = explode('=', $pair, 2) + [1 => null];
                if ($value === null || ($decoded = urldecode($value)) === ($rewritten = $this->linksToUpstream($decoded, $origin))) {
                    return $pair;
                }

                return $name.'='.urlencode($rewritten);
            }, explode('&', $body)));
        }
        if ($type !== 'multipart/form-data') {
            return $this->linksToUpstream($body, $origin);
        }

        if (!preg_match('{boundary="?([^";]+)"?}i', $contentType, $m)) {
            return $body;
        }
        $delimiter = '--'.$m[1];
        $parts = explode($delimiter, $body);
        foreach ($parts as $i => $part) {
            $split = strpos($part, "\r\n\r\n");
            // uploaded files stay untouched
            if ($split === false || stripos(substr($part, 0, $split), 'filename=') !== false) {
                continue;
            }
            $parts[$i] = substr($part, 0, $split + 4).$this->linksToUpstream(substr($part, $split + 4), $origin);
        }

        return implode($delimiter, $parts);
    }

    /**
     * The site's copy and share buttons build links from location.origin, make them share the real site.
     */
    private function injectClipboardFix(string $html, string $origin): string
    {
        if (false === ($head = stripos($html, '<head')) || false === ($end = strpos($html, '>', $head))) {
            return $html;
        }
        $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES;
        $script = sprintf(<<<'JS'
            <script>(() => {
                const local = new RegExp(%s + '(?:' + %s + '(?![\\w-])|(?![\\w.:-]))', 'g');
                const fix = (value) => typeof value === 'string' ? value.replace(local, %s) : value;
                const clipboard = navigator.clipboard;
                if (clipboard?.writeText) {
                    const writeText = clipboard.writeText.bind(clipboard);
                    clipboard.writeText = (text) => writeText(fix(text));
                }
                if (navigator.share) {
                    const share = navigator.share.bind(navigator);
                    navigator.share = (data) => share({ ...data, url: fix(data?.url), text: fix(data?.text) });
                }
            })();</script>
            JS,
            json_encode(preg_quote($origin), $flags),
            json_encode(preg_quote($this->localRoot()), $flags),
            json_encode($this->upstream, $flags),
        );

        return substr_replace($html, $script, $end + 1, 0);
    }

    private function toUpstream(string $value, string $origin): string
    {
        return str_starts_with($value, $origin) ? $this->upstream.substr($value, strlen($origin)) : $value;
    }

    private function localRoot(): string
    {
        return $this->prefix === '/' ? '' : $this->prefix;
    }

    private function stripCookieDomain(string $cookie): string
    {
        return preg_replace('{;\s*domain=[^;]*}i', '', $cookie);
    }
}
