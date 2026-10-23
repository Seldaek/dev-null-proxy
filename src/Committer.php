<?php declare(strict_types=1);

namespace DevNullProxy;

use Amp\Http\Client\BufferedContent;
use Amp\Http\Client\Form;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;

/**
 * Commits to /dev/null the way its own `commit` script does: no login, the payload is signed with an SSH key
 * that is on your GitHub account, and the site checks it against the keys GitHub publishes.
 */
final class Committer
{
    public const MAX_IMAGE_SIZE = 10240000;

    private readonly string $baseUrl;
    private readonly HttpClient $client;

    public function __construct(string $baseUrl)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        if (!str_starts_with($this->baseUrl, 'https://') && !preg_match('{^http://(localhost|127\.0\.0\.1)(:\d+)?$}', $this->baseUrl)) {
            throw new \RuntimeException('Refusing to send commits to '.$this->baseUrl.': it is not an https:// URL.');
        }
        $this->client = (new HttpClientBuilder())->followRedirects(0)->retry(0)->build();
    }

    /**
     * @param string|null $image raw JPEG, PNG or WebP data
     * @return string the site's answer, e.g. "Committed: https://..."
     */
    public function commit(string $message, ?string $image = null, string $replyTo = ''): string
    {
        if (preg_match('{[^A-Za-z0-9:/._@-]}', $replyTo)) {
            throw new \RuntimeException('A reply takes the hash of a commit or its link.');
        }

        $tmp = $this->makeTempDir();
        try {
            $candidates = $this->candidateKeys();
            if ($candidates === []) {
                throw new \RuntimeException('No Ed25519 or RSA SSH key found in your SSH agent or in ~/.ssh.');
            }

            $answer = $this->request('/api/cli/key-lookups', implode("\n", $candidates)."\n");
            // only ever sign with one of our own keys, whatever the site answers
            $key = self::keyId(strtok($answer, "\n") ?: '');
            if (!in_array($key, $candidates, true)) {
                throw new \RuntimeException('Unexpected answer from '.$this->baseUrl.'.');
            }

            $namespace = $image !== null ? 'devnull-commit-images' : 'devnull-commit';
            $lines = [(string) time(), bin2hex(random_bytes(16)), $replyTo];
            if ($image !== null) {
                file_put_contents($tmp.'/image-1', $image);
                $lines[] = hash('sha256', $image);
            }
            $lines[] = $message;
            file_put_contents($tmp.'/commit', implode("\n", $lines));

            $signature = $this->sign($this->signingKey($key, $tmp), $namespace, $tmp.'/commit');

            if ($image === null) {
                return $this->request('/api/cli/commits', file_get_contents($tmp.'/commit'), ['x-ssh-signature' => $signature]);
            }

            // from memory: Form::addFile() would need amphp/file
            $form = new Form();
            $form->addStream('payload', BufferedContent::fromString(file_get_contents($tmp.'/commit'), 'application/octet-stream'), 'commit');
            $form->addStream('images[]', BufferedContent::fromString($image, self::imageType($image)), 'image-1');

            return $this->request('/api/cli/commits', $form, ['x-ssh-signature' => $signature], 600);
        } finally {
            foreach (['commit', 'commit.sig', 'key.pub', 'image-1'] as $file) {
                @unlink($tmp.'/'.$file);
            }
            @rmdir($tmp);
        }
    }

    public static function imageType(string $data): ?string
    {
        return match (true) {
            str_starts_with($data, "\x89PNG\r\n\x1a\n") => 'image/png',
            str_starts_with($data, "\xFF\xD8\xFF") => 'image/jpeg',
            str_starts_with($data, 'RIFF') && substr($data, 8, 4) === 'WEBP' => 'image/webp',
            default => null,
        };
    }

    /**
     * @return list<string> "<type> <base64>" of every usable public key
     */
    private function candidateKeys(): array
    {
        $lines = explode("\n", $this->run(['ssh-add', '-L']) ?? '');
        foreach (glob($this->home().'/.ssh/*.pub') ?: [] as $pub) {
            if (is_file(substr($pub, 0, -4))) {
                $lines[] = (string) strtok((string) file_get_contents($pub), "\n");
            }
        }

        $keys = [];
        foreach ($lines as $line) {
            if (preg_match('{^(ssh-ed25519|ssh-rsa) }', $line)) {
                $keys[] = self::keyId($line);
            }
        }

        return array_values(array_unique($keys));
    }

    /**
     * Through the agent if it has the key, otherwise with the private key file.
     */
    private function signingKey(string $key, string $tmp): string
    {
        foreach (explode("\n", $this->run(['ssh-add', '-L']) ?? '') as $line) {
            if (self::keyId($line) === $key) {
                file_put_contents($tmp.'/key.pub', $key."\n");

                return $tmp.'/key.pub';
            }
        }
        foreach (glob($this->home().'/.ssh/*.pub') ?: [] as $pub) {
            if (self::keyId((string) strtok((string) file_get_contents($pub), "\n")) === $key && is_file(substr($pub, 0, -4))) {
                return substr($pub, 0, -4);
            }
        }

        throw new \RuntimeException('Could not find the private key of '.$key.'.');
    }

    private function sign(string $signingKey, string $namespace, string $file): string
    {
        // passphrase prompts go to /dev/tty, keep ssh-keygen off our stdin
        $proc = proc_open(['ssh-keygen', '-Y', 'sign', '-n', $namespace, '-f', $signingKey, $file], [['file', '/dev/null', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            throw new \RuntimeException('Could not run ssh-keygen.');
        }
        stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        if (proc_close($proc) !== 0) {
            throw new \RuntimeException('Could not sign with '.$signingKey.': '.self::sanitize(trim((string) $error)));
        }

        $signature = implode('', array_filter(file($file.'.sig', FILE_IGNORE_NEW_LINES) ?: [], static fn (string $l) => !str_contains($l, '-----')));
        if (!preg_match('{^[A-Za-z0-9+/=]+$}', $signature)) {
            throw new \RuntimeException('ssh-keygen produced an unexpected signature.');
        }

        return $signature;
    }

    /**
     * @param array<string, string> $headers
     */
    private function request(string $path, string|Form $body, array $headers = [], int $timeout = 30): string
    {
        $request = new Request($this->baseUrl.$path, 'POST');
        $request->setTransferTimeout($timeout);
        $request->setInactivityTimeout(60);
        if (is_string($body)) {
            $request->setHeader('content-type', 'text/plain; charset=utf-8');
        }
        $request->setBody($body);
        foreach ($headers as $name => $value) {
            $request->setHeader($name, $value);
        }

        try {
            $response = $this->client->request($request);
            $text = self::sanitize($response->getBody()->buffer(limit: 64 * 1024));
        } catch (\Amp\Http\Client\HttpException $e) {
            throw new \RuntimeException('Could not reach '.$this->baseUrl.': '.$e->getMessage());
        }

        $status = $response->getStatus();
        if ($status < 200 || $status > 299) {
            throw new \RuntimeException(trim($text) !== '' ? trim($text) : 'Unexpected answer from '.$this->baseUrl.' (HTTP '.$status.').');
        }

        return $text;
    }

    /**
     * @param list<string> $cmd
     */
    private function run(array $cmd): ?string
    {
        $proc = @proc_open($cmd, [['file', '/dev/null', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($proc)) {
            return null;
        }
        $out = stream_get_contents($pipes[1]);
        proc_close($proc);

        return $out === false ? null : $out;
    }

    private function makeTempDir(): string
    {
        $dir = sys_get_temp_dir().'/devnull.'.bin2hex(random_bytes(5));
        if (!@mkdir($dir, 0700)) {
            throw new \RuntimeException('Could not create a private temporary directory.');
        }

        return $dir;
    }

    private function home(): string
    {
        return (string) (getenv('HOME') ?: (posix_getpwuid(posix_geteuid())['dir'] ?? ''));
    }

    private static function keyId(string $line): string
    {
        return implode(' ', array_slice(preg_split('{\s+}', trim($line)) ?: [], 0, 2));
    }

    /**
     * Strips control characters (terminal escapes) from text we print, keeping newlines and tabs.
     */
    private static function sanitize(string $text): string
    {
        return (string) preg_replace('{[\x00-\x08\x0B-\x1F\x7F]}', '', $text);
    }
}
