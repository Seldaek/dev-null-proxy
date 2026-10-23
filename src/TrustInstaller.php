<?php declare(strict_types=1);

namespace DevNullProxy;

/**
 * Adds the local CA to the OS trust store. Runs the commands it can and prints the ones needing root.
 */
final class TrustInstaller
{
    public static function isWsl(): bool
    {
        return PHP_OS_FAMILY === 'Linux' && str_contains(strtolower((string) @file_get_contents('/proc/version')), 'microsoft');
    }

    /**
     * @param callable(string): void $out
     */
    public function install(string $caCert, callable $out): bool
    {
        return match (true) {
            PHP_OS_FAMILY === 'Windows' => $this->run(['certutil', '-addstore', '-user', 'Root', $caCert], $out),
            PHP_OS_FAMILY === 'Darwin' => $this->run(['security', 'add-trusted-cert', '-r', 'trustRoot', '-k', getenv('HOME').'/Library/Keychains/login.keychain-db', $caCert], $out),
            self::isWsl() => $this->installWsl($caCert, $out),
            default => $this->installLinux($caCert, $out),
        };
    }

    /**
     * @param callable(string): void $out
     */
    private function installWsl(string $caCert, callable $out): bool
    {
        // the browser runs on Windows, so that's the store that matters; copy out of the WSL fs first
        $winTemp = trim((string) shell_exec('cmd.exe /c "echo %TEMP%" 2>/dev/null'));
        $linuxTemp = $winTemp !== '' ? trim((string) shell_exec('wslpath -u '.escapeshellarg($winTemp))) : '';
        if ($linuxTemp === '' || !is_dir($linuxTemp)) {
            $out('<error>Could not locate the Windows temp dir. Import '.$caCert.' into "Trusted Root Certification Authorities" manually.</error>');

            return false;
        }

        copy($caCert, $linuxTemp.'/dev-null-proxy-ca.crt');
        $out('A Windows dialog will ask you to confirm installing the certificate.');

        return $this->run(['certutil.exe', '-addstore', '-user', 'Root', $winTemp.'\\dev-null-proxy-ca.crt'], $out);
    }

    /**
     * @param callable(string): void $out
     */
    private function installLinux(string $caCert, callable $out): bool
    {
        $ok = true;
        if (is_dir('/usr/local/share/ca-certificates')) {
            $cmds = ['sudo cp '.escapeshellarg($caCert).' /usr/local/share/ca-certificates/dev-null-proxy.crt', 'sudo update-ca-certificates'];
        } elseif (is_dir('/etc/pki/ca-trust/source/anchors')) {
            $cmds = ['sudo cp '.escapeshellarg($caCert).' /etc/pki/ca-trust/source/anchors/dev-null-proxy.crt', 'sudo update-ca-trust'];
        } else {
            $cmds = ['sudo trust anchor '.escapeshellarg($caCert)];
        }
        foreach ($cmds as $cmd) {
            $ok = $ok && $this->run($cmd, $out);
        }

        // Chrome/Firefox on Linux use their own NSS db
        $nssDb = getenv('HOME').'/.pki/nssdb';
        if (is_dir($nssDb)) {
            if (trim((string) shell_exec('command -v certutil')) === '') {
                $out('Install libnss3-tools (certutil) and re-run to trust the CA in Chrome as well.');
            } else {
                $this->run(['certutil', '-d', 'sql:'.$nssDb, '-A', '-t', 'C,,', '-n', 'dev-null-proxy', '-i', $caCert], $out);
            }
        }

        return $ok;
    }

    /**
     * @param list<string>|string $cmd
     * @param callable(string): void $out
     */
    private function run(array|string $cmd, callable $out): bool
    {
        $out('$ '.(is_array($cmd) ? implode(' ', array_map(escapeshellarg(...), $cmd)) : $cmd));
        $proc = proc_open($cmd, [STDIN, STDOUT, STDERR], $pipes);
        if (!is_resource($proc)) {
            return false;
        }

        return proc_close($proc) === 0;
    }
}
