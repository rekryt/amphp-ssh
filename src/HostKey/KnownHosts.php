<?php declare(strict_types=1);

namespace Amp\Ssh\HostKey;

use function Amp\File\exists;
use function Amp\File\read;

/**
 * Checks host keys against an OpenSSH known_hosts file.
 *
 * Understands plain host names, the "[host]:port" form used for non-default
 * ports, wildcard patterns, and the |1| hashed entries OpenSSH writes by
 * default. Certificate authority entries are recognised but not honoured:
 * pretending to validate a certificate we cannot check would be worse than
 * saying so.
 */
final class KnownHosts implements HostKeyVerifier {
    private string $path;

    private bool $rejectUnknown;

    /**
     * @param string|null $path          Defaults to ~/.ssh/known_hosts.
     * @param bool        $rejectUnknown Whether a host with no entry at all is
     *                                   an error. Leaving it true is the point
     *                                   of the class; turning it off downgrades
     *                                   to "warn me only if the key changed".
     */
    public function __construct(?string $path = null, bool $rejectUnknown = true) {
        $this->path = $path ?? self::defaultPath();
        $this->rejectUnknown = $rejectUnknown;
    }

    public static function defaultPath(): string {
        $home = \getenv('HOME') ?: \getenv('USERPROFILE') ?: '';

        return \rtrim($home, '/\\') . '/.ssh/known_hosts';
    }

    public function verify(string $host, int $port, string $format, string $key): void {
        if (!exists($this->path)) {
            if ($this->rejectUnknown) {
                throw new HostKeyVerificationException(\sprintf(
                    'No known_hosts file at %s, so the identity of %s cannot be established.',
                    $this->path,
                    self::describe($host, $port)
                ));
            }

            return;
        }

        $entries = self::parse(read($this->path));

        if (Certificate::isCertificateAlgorithm($format)) {
            $this->verifyCertificate($host, $port, $key, $entries);

            return;
        }

        $encoded = \base64_encode($key);
        $matchedHost = false;

        foreach ($entries as $entry) {
            if (!self::matchesHost($entry['patterns'], $host, $port)) {
                continue;
            }

            // A CA line says nothing about a plain key.
            if ($entry['marker'] === '@cert-authority') {
                continue;
            }

            if ($entry['key'] !== $encoded) {
                $matchedHost = true;

                continue;
            }

            if ($entry['marker'] === '@revoked') {
                throw new HostKeyVerificationException(\sprintf(
                    'The host key offered by %s is marked revoked in %s.',
                    self::describe($host, $port),
                    $this->path
                ));
            }

            return;
        }

        if ($matchedHost) {
            throw new HostKeyVerificationException(\sprintf(
                'The host key offered by %s does not match the one recorded in %s. '
                    . 'Either the host was rebuilt, or the connection is being intercepted.',
                self::describe($host, $port),
                $this->path
            ));
        }

        if ($this->rejectUnknown) {
            throw new HostKeyVerificationException(\sprintf(
                '%s is not listed in %s, so its identity cannot be established.',
                self::describe($host, $port),
                $this->path
            ));
        }
    }

    /**
     * Validates a certificate and the authority that signed it.
     *
     * @param array<int, array{marker: string, patterns: string, key: string}> $entries
     */
    private function verifyCertificate(string $host, int $port, string $blob, array $entries): void {
        $certificate = Certificate::parse($blob);

        $authorities = [];

        foreach ($entries as $entry) {
            if ($entry['marker'] === '@cert-authority' && self::matchesHost($entry['patterns'], $host, $port)) {
                $authorities[] = $entry['key'];
            }
        }

        if ($authorities === []) {
            throw new HostKeyVerificationException(\sprintf(
                '%s presented a host certificate, but %s lists no @cert-authority for it.',
                self::describe($host, $port),
                $this->path
            ));
        }

        $certificate->validate(
            $host,
            static fn (string $authorityKey): bool => \in_array(\base64_encode($authorityKey), $authorities, true)
        );
    }

    /**
     * @return array<int, array{marker: string, patterns: string, key: string}>
     */
    private static function parse(string $contents): array {
        $entries = [];

        foreach (\explode("\n", $contents) as $line) {
            $entry = self::parseLine($line);

            if ($entry !== null) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * @return array{marker: string, patterns: string, key: string}|null
     */
    private static function parseLine(string $line): ?array {
        $line = \trim($line);

        if ($line === '' || $line[0] === '#') {
            return null;
        }

        $fields = \preg_split('/\s+/', $line);
        $marker = '';

        if (isset($fields[0]) && \str_starts_with($fields[0], '@')) {
            $marker = \array_shift($fields);
        }

        // patterns, key type, base64 key
        if (\count($fields) < 3) {
            return null;
        }

        return ['marker' => $marker, 'patterns' => $fields[0], 'key' => $fields[2]];
    }

    private static function matchesHost(string $patterns, string $host, int $port): bool {
        if (\str_starts_with($patterns, '|1|')) {
            return self::matchesHashed($patterns, $host, $port);
        }

        $candidates = [$host];

        // OpenSSH only writes the bracketed form for non-default ports.
        if ($port !== 22) {
            \array_unshift($candidates, \sprintf('[%s]:%d', $host, $port));
        }

        foreach (\explode(',', $patterns) as $pattern) {
            $negated = \str_starts_with($pattern, '!');
            $pattern = $negated ? \substr($pattern, 1) : $pattern;

            foreach ($candidates as $candidate) {
                if (self::matchesPattern($pattern, $candidate)) {
                    return !$negated;
                }
            }
        }

        return false;
    }

    /**
     * Compares one known_hosts pattern against one candidate host.
     *
     * fnmatch() is only used when the pattern actually has a wildcard in it:
     * the "[host]:port" form is otherwise read as a character class, so an
     * entry for a non-default port would never match itself.
     */
    private static function matchesPattern(string $pattern, string $candidate): bool {
        if (\strcspn($pattern, '*?') === \strlen($pattern)) {
            return \strcasecmp($pattern, $candidate) === 0;
        }

        return \fnmatch($pattern, $candidate, FNM_CASEFOLD);
    }

    /**
     * Hashed entries look like |1|<base64 salt>|<base64 HMAC-SHA1 of the host>.
     */
    private static function matchesHashed(string $pattern, string $host, int $port): bool {
        $parts = \explode('|', $pattern);

        if (\count($parts) !== 4) {
            return false;
        }

        $salt = \base64_decode($parts[2], true);
        $expected = $parts[3];

        if ($salt === false) {
            return false;
        }

        $candidates = [$host];

        if ($port !== 22) {
            $candidates[] = \sprintf('[%s]:%d', $host, $port);
        }

        foreach ($candidates as $candidate) {
            $hash = \base64_encode(\hash_hmac('sha1', $candidate, $salt, true));

            if (\hash_equals($expected, $hash)) {
                return true;
            }
        }

        return false;
    }

    private static function describe(string $host, int $port): string {
        return $port === 22 ? $host : \sprintf('[%s]:%d', $host, $port);
    }
}
