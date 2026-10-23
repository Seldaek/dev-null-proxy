<?php declare(strict_types=1);

namespace DevNullProxy;

/**
 * A named pipe where every write (open, write, close) becomes a commit, e.g. `echo hi > /dev/NULL`.
 */
final class Pipe
{
    public const DEFAULT_PATH = '/dev/NULL';
    // /dev/null followed by a zero-width space: looks like /dev/null, but isn't
    public const DEFAULT_ALIAS = "/dev/null\u{200B}";
    private const TMPFILES_CONF = '/etc/tmpfiles.d/dev-null-proxy.conf';
    private const MAX_TEXT_SIZE = 100 * 1024;

    /**
     * @param callable(string): void $out
     */
    public static function install(string $path, ?string $alias, callable $out): void
    {
        [$user, $group] = self::owner();

        if (file_exists($path) && filetype($path) !== 'fifo') {
            throw new \RuntimeException($path.' exists and is not a pipe, not touching it.');
        }
        if (!file_exists($path)) {
            if (!posix_mkfifo($path, 0600)) {
                throw new \RuntimeException('Could not create '.$path.(posix_geteuid() !== 0 ? ', run this with sudo.' : '.'));
            }
            $out('Created '.$path);
        }
        // only you can write to it, so nobody else can commit as you
        chmod($path, 0600);
        if (posix_geteuid() === 0) {
            chown($path, $user);
            chgrp($path, $group);
        }

        if ($alias !== null) {
            if (is_link($alias) && readlink($alias) !== $path) {
                unlink($alias);
            }
            if (!is_link($alias)) {
                if (file_exists($alias) || !symlink($path, $alias)) {
                    throw new \RuntimeException('Could not create '.self::visible($alias));
                }
                $out('Created '.self::visible($alias).' -> '.$path);
            }
        }

        // /dev is rebuilt at boot, systemd-tmpfiles can recreate the pipe every time
        if (str_starts_with($path, '/dev/') && is_dir(dirname(self::TMPFILES_CONF)) && posix_geteuid() === 0) {
            $conf = "# dev-null-proxy: what gets written to these is committed to dev-null.sh\n"
                .sprintf("p %s 0600 %s %s -\n", self::escape($path), $user, $group)
                .($alias !== null ? sprintf("L %s - - - - %s\n", self::escape($alias), self::escape($path)) : '');
            file_put_contents(self::TMPFILES_CONF, $conf);
            $out('Wrote '.self::TMPFILES_CONF.' so it comes back after a reboot');
        } elseif (str_starts_with($path, '/dev/')) {
            $out('Note: '.$path.' disappears on reboot, run this again then.');
        }
    }

    /**
     * @param callable(string): void $out
     */
    public static function uninstall(string $path, ?string $alias, callable $out): void
    {
        foreach (array_filter([$alias, $path]) as $file) {
            if (is_link($file) || (file_exists($file) && filetype($file) === 'fifo')) {
                unlink($file) ? $out('Removed '.self::visible($file)) : $out('Could not remove '.self::visible($file));
            }
        }
        if (is_file(self::TMPFILES_CONF) && @unlink(self::TMPFILES_CONF)) {
            $out('Removed '.self::TMPFILES_CONF);
        }
    }

    /**
     * Reads the pipe forever, committing each write.
     *
     * @param callable(string): void $out
     * @param callable(string): void $err
     */
    public static function serve(string $path, Committer $committer, callable $out, callable $err): never
    {
        if (!file_exists($path) || filetype($path) !== 'fifo') {
            throw new \RuntimeException($path.' is not a pipe yet, create it with: sudo dev-null-proxy install-pipe');
        }

        $out('Waiting for writes to '.$path.' (Ctrl+C to stop)');
        while (true) {
            // blocks until someone opens the pipe for writing, then reads until every writer closed it
            $handle = @fopen($path, 'r');
            if ($handle === false) {
                throw new \RuntimeException('Could not open '.$path);
            }
            $data = (string) stream_get_contents($handle, Committer::MAX_IMAGE_SIZE + 1);
            $tooLarge = !feof($handle);
            while (!feof($handle)) {
                fread($handle, 65536);
            }
            fclose($handle);

            try {
                $result = self::commitData($data, $tooLarge, $committer);
                if ($result !== null) {
                    $out(trim($result));
                }
            } catch (\Throwable $e) {
                $err('Not committed: '.$e->getMessage());
            }
        }
    }

    private static function commitData(string $data, bool $tooLarge, Committer $committer): ?string
    {
        if (Committer::imageType($data) !== null) {
            if ($tooLarge) {
                throw new \RuntimeException('images can be up to 10 MB.');
            }

            return $committer->commit('', $data);
        }

        // what `echo` adds isn't part of the message
        $message = rtrim($data, "\r\n");
        if (trim($message) === '') {
            return null;
        }
        if ($tooLarge || strlen($message) > self::MAX_TEXT_SIZE) {
            throw new \RuntimeException('that is way too long for a commit.');
        }
        if (!preg_match('//u', $message) || preg_match('{[\x00-\x08\x0E-\x1F]}', $message)) {
            throw new \RuntimeException('that looks like binary data (only text, PNG, JPEG and WebP go through).');
        }

        return $committer->commit($message);
    }

    /**
     * @return array{string, string} user and group owning the pipe: whoever ran sudo
     */
    private static function owner(): array
    {
        $pw = (($sudoUser = getenv('SUDO_USER')) ? posix_getpwnam($sudoUser) : false) ?: posix_getpwuid(posix_geteuid());
        $group = posix_getgrgid($pw['gid']);

        return [$pw['name'], $group['name'] ?? (string) $pw['gid']];
    }

    /**
     * tmpfiles.d fields take C escapes, which keeps the zero-width space visible in the file.
     */
    private static function escape(string $path): string
    {
        return preg_replace_callback('{[^\x21-\x7E]}', static fn (array $m) => sprintf('\\x%02x', ord($m[0])), $path);
    }

    private static function visible(string $path): string
    {
        return str_replace("\u{200B}", '<U+200B>', $path);
    }
}
