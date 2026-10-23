<?php declare(strict_types=1);

namespace DevNullProxy;

use Amp\Cancellation;
use Amp\Dns\DnsConfig;
use Amp\Dns\DnsRecord;
use Amp\Dns\DnsResolver;
use Amp\Dns\Rfc1035StubDnsResolver;
use Amp\Dns\StaticDnsConfigLoader;

/**
 * When the hosts file points the upstream at the proxy itself, ask public DNS where it really lives.
 */
final class UpstreamDnsResolver implements DnsResolver
{
    private readonly DnsResolver $public;

    public function __construct(private readonly DnsResolver $system, private readonly string $upstreamHost)
    {
        $this->public = new Rfc1035StubDnsResolver(null, new StaticDnsConfigLoader(new DnsConfig(['1.1.1.1:53', '8.8.8.8:53', '9.9.9.9:53'])));
    }

    public function resolve(string $name, ?int $typeRestriction = null, ?Cancellation $cancellation = null): array
    {
        if (strtolower($name) !== $this->upstreamHost) {
            return $this->system->resolve($name, $typeRestriction, $cancellation);
        }

        $records = $this->system->resolve($name, $typeRestriction, $cancellation);
        if (!self::allLoopback($records)) {
            return $records;
        }

        return $this->public->resolve($name, $typeRestriction, $cancellation);
    }

    public function query(string $name, int $type, ?Cancellation $cancellation = null): array
    {
        if (strtolower($name) === $this->upstreamHost) {
            return $this->public->query($name, $type, $cancellation);
        }

        return $this->system->query($name, $type, $cancellation);
    }

    /**
     * Whether the upstream host currently resolves to this machine, i.e. the hosts override is in place.
     */
    public function isOverridden(): bool
    {
        try {
            if (self::allLoopback($this->system->resolve($this->upstreamHost))) {
                return true;
            }
        } catch (\Throwable) {
        }

        // on WSL the browser uses the Windows hosts file, which /etc/hosts doesn't necessarily mirror
        if (TrustInstaller::isWsl() && is_readable($winHosts = '/mnt/c/Windows/System32/drivers/etc/hosts')) {
            foreach (file($winHosts, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
                $parts = preg_split('{\s+}', trim(explode('#', $line)[0]));
                if (count($parts) >= 2 && self::isLoopback($parts[0]) && in_array($this->upstreamHost, array_map(strtolower(...), array_slice($parts, 1)), true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param list<DnsRecord> $records
     */
    private static function allLoopback(array $records): bool
    {
        foreach ($records as $record) {
            if (!self::isLoopback($record->getValue())) {
                return false;
            }
        }

        return $records !== [];
    }

    private static function isLoopback(string $ip): bool
    {
        return $ip === '::1' || str_starts_with($ip, '127.') || $ip === '0.0.0.0';
    }
}
