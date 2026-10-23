<?php declare(strict_types=1);

namespace DevNullProxy;

/**
 * Minimal local CA: one root you trust once, plus a leaf cert for the proxied hostname.
 */
final class CertificateAuthority
{
    private const CA_DAYS = 3650;
    // browsers cap leaf validity at 398 days, even for private roots in some cases
    private const LEAF_DAYS = 397;

    public function __construct(private readonly string $dir)
    {
    }

    public static function defaultDir(): string
    {
        if (($dir = getenv('DEV_NULL_PROXY_HOME')) !== false && $dir !== '') {
            return $dir;
        }
        if (PHP_OS_FAMILY === 'Windows') {
            return getenv('LOCALAPPDATA').'\\dev-null-proxy';
        }
        // under sudo, keep using the invoking user's CA, which is the one they trusted
        $sudoUser = getenv('SUDO_USER');
        if ($sudoUser && function_exists('posix_getpwnam') && ($pw = posix_getpwnam($sudoUser))) {
            return $pw['dir'].'/.config/dev-null-proxy';
        }
        $home = getenv('HOME') ?: (posix_getpwuid(posix_geteuid())['dir'] ?? '/tmp');
        $config = getenv('XDG_CONFIG_HOME') ?: $home.'/.config';

        return $config.'/dev-null-proxy';
    }

    public function caCertPath(): string
    {
        return $this->dir.'/ca.crt';
    }

    /**
     * @param non-empty-list<string> $hostnames
     * @return array{string, string} cert and key paths
     */
    public function leafFor(array $hostnames): array
    {
        $this->ensureCa();

        $sans = array_merge(array_map(static fn (string $h) => 'DNS:'.$h, array_unique($hostnames)), ['DNS:localhost', 'IP:127.0.0.1', 'IP:::1']);
        $cert = $this->dir.'/'.$hostnames[0].'.crt';
        $key = $this->dir.'/'.$hostnames[0].'.key';
        if (!is_file($cert) || !is_file($key) || $this->expiresSoon($cert) || !$this->isSignedByCa($cert) || !$this->hasSans($cert, $sans)) {
            $this->issueLeaf($hostnames[0], $sans, $cert, $key);
        }

        return [$cert, $key];
    }

    public function ensureCa(): void
    {
        if (is_file($this->caCertPath()) && is_file($this->dir.'/ca.key')) {
            return;
        }

        if (!is_dir($this->dir) && !mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new \RuntimeException('Could not create '.$this->dir);
        }

        $key = $this->newKey();
        $user = get_current_user() ?: 'local';
        $csr = openssl_csr_new(['commonName' => 'dev-null-proxy local CA ('.$user.')', 'organizationName' => 'dev-null-proxy'], $key, $this->opts('v3_ca'));
        $cert = openssl_csr_sign($csr, null, $key, self::CA_DAYS, $this->opts('v3_ca'), random_int(1, PHP_INT_MAX));
        if ($cert === false) {
            throw new \RuntimeException('Failed to create CA: '.openssl_error_string());
        }

        openssl_pkey_export_to_file($key, $this->dir.'/ca.key');
        chmod($this->dir.'/ca.key', 0600);
        openssl_x509_export_to_file($cert, $this->caCertPath());
    }

    /**
     * @param list<string> $sans
     */
    private function issueLeaf(string $hostname, array $sans, string $certPath, string $keyPath): void
    {
        $caCert = file_get_contents($this->caCertPath());
        $caKey = openssl_pkey_get_private(file_get_contents($this->dir.'/ca.key'));

        $key = $this->newKey();
        $csr = openssl_csr_new(['commonName' => $hostname], $key, $this->opts('v3_leaf', $sans));
        $cert = openssl_csr_sign($csr, $caCert, $caKey, self::LEAF_DAYS, $this->opts('v3_leaf', $sans), random_int(1, PHP_INT_MAX));
        if ($cert === false) {
            throw new \RuntimeException('Failed to issue certificate: '.openssl_error_string());
        }

        openssl_pkey_export_to_file($key, $keyPath);
        chmod($keyPath, 0600);
        openssl_x509_export_to_file($cert, $certPath);
    }

    private function expiresSoon(string $certPath): bool
    {
        $info = openssl_x509_parse(file_get_contents($certPath));

        return !$info || $info['validTo_time_t'] < time() + 7 * 86400;
    }

    /**
     * @param list<string> $sans
     */
    private function hasSans(string $certPath, array $sans): bool
    {
        $info = openssl_x509_parse(file_get_contents($certPath));
        // openssl prints "DNS:dev, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1", so compare the DNS names only
        preg_match_all('{DNS:([^,\s]+)}', $info['extensions']['subjectAltName'] ?? '', $m);
        $wanted = array_map(static fn (string $s) => substr($s, 4), array_filter($sans, static fn (string $s) => str_starts_with($s, 'DNS:')));
        sort($m[1]);
        sort($wanted);

        return $m[1] === $wanted;
    }

    private function isSignedByCa(string $certPath): bool
    {
        $caKey = openssl_pkey_get_public(file_get_contents($this->caCertPath()));

        return openssl_x509_verify(file_get_contents($certPath), $caKey) === 1;
    }

    private function newKey(): \OpenSSLAsymmetricKey
    {
        return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'])
            ?: throw new \RuntimeException('Failed to generate key: '.openssl_error_string());
    }

    /**
     * ext-openssl only takes x509 extensions from a config file, so write a throwaway one.
     *
     * @param list<string> $sans
     * @return array<string, mixed>
     */
    private function opts(string $section, array $sans = []): array
    {
        $config = <<<CNF
            [req]
            distinguished_name = dn
            [dn]
            [v3_ca]
            basicConstraints = critical, CA:TRUE, pathlen:0
            keyUsage = critical, keyCertSign, cRLSign
            subjectKeyIdentifier = hash
            [v3_leaf]
            basicConstraints = critical, CA:FALSE
            keyUsage = critical, digitalSignature, keyEncipherment
            extendedKeyUsage = serverAuth
            subjectKeyIdentifier = hash
            authorityKeyIdentifier = keyid
            subjectAltName = {$this->sanList($sans)}

            CNF;

        $file = $this->dir.'/openssl.cnf';
        file_put_contents($file, $config);

        return ['config' => $file, 'x509_extensions' => $section, 'digest_alg' => 'sha256'];
    }

    /**
     * @param list<string> $sans
     */
    private function sanList(array $sans): string
    {
        return $sans === [] ? 'DNS:localhost' : implode(', ', $sans);
    }
}
