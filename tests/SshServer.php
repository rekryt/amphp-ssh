<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use Amp\Ssh\Authentication\Authentication;
use Amp\Ssh\Authentication\UsernamePassword;
use function Amp\Ssh\connect;
use Amp\Ssh\HostKey\AcceptAnyHostKey;
use Amp\Ssh\SshResource;

/**
 * Locates the sshd the integration tests talk to.
 *
 * The address used to be hardcoded, which meant the whole suite failed on any
 * machine without the test container running. It is now configuration, and
 * tests that need a server skip themselves when there is none.
 */
final class SshServer {
    private static ?bool $available = null;

    private static ?string $failure = null;

    public static function host(): string {
        return \getenv('SSH_LOCAL_HOST') ?: '127.0.0.1';
    }

    public static function port(): int {
        return (int) (\getenv('SSH_LOCAL_PORT') ?: '2222');
    }

    public static function uri(): string {
        return self::host() . ':' . self::port();
    }

    public static function user(): string {
        return \getenv('SSH_LOCAL_USER') ?: 'root';
    }

    public static function password(): string {
        return \getenv('SSH_LOCAL_PASSWORD') ?: 'root';
    }

    /**
     * Integration tests are opt-in.
     *
     * Without this the suite would dial 127.0.0.1:2222 and try to log in as
     * root on whatever happens to answer - which on a developer machine is
     * quite likely somebody else's SSH server. Failed password attempts
     * against an unrelated host are not something a unit test run should be
     * doing, so the address has to be stated explicitly.
     */
    public static function isEnabled(): bool {
        // An empty value counts as unset: CI disables the integration jobs by
        // blanking these rather than by removing them.
        return (\getenv('SSH_LOCAL_HOST') ?: '') !== '' || (\getenv('SSH_LOCAL_PORT') ?: '') !== '';
    }

    /**
     * Probes with a full connect rather than a bare TCP dial.
     *
     * A listening port proves nothing: a server may be reachable and still
     * share no host key algorithm with this client, which is exactly what
     * happens against a current OpenSSH. Distinguishing "no server" from
     * "server we cannot talk to" is the difference between a useful skip
     * message and a wall of identical handshake errors.
     */
    public static function isAvailable(): bool {
        if (!self::isEnabled()) {
            return false;
        }

        if (self::$available !== null) {
            return self::$available;
        }

        try {
            $resource = self::connect();
            $resource->close();

            self::$failure = null;

            return self::$available = true;
        } catch (\Throwable $exception) {
            self::$failure = \get_class($exception) . ': ' . $exception->getMessage();

            return self::$available = false;
        }
    }

    public static function skipReason(): string {
        if (!self::isEnabled()) {
            return "Integration tests are disabled: set SSH_LOCAL_HOST (and optionally SSH_LOCAL_PORT, "
                . "SSH_LOCAL_USER, SSH_LOCAL_PASSWORD) to point at a test server.\n"
                . "A disposable one can be started with:\n"
                . "  docker build -f docker/legacy.Dockerfile -t amphp-ssh-legacy .\n"
                . '  docker run -d -p 2222:22 amphp-ssh-legacy';
        }

        return \sprintf(
            'Cannot use the SSH server configured at %s (%s).',
            self::uri(),
            self::$failure ?? 'unreachable'
        );
    }

    public static function connect(): SshResource {
        return self::connectWith(new UsernamePassword(self::user(), self::password()));
    }

    /**
     * The one place an integration test opens a connection.
     *
     * The test server is disposable and its host key changes with every build,
     * so there is nothing to pin it against. Opting out explicitly is the point
     * of AcceptAnyHostKey; production code should never reach for it.
     *
     * Going through here rather than calling connect() per test is what makes
     * that opt-out reliable. A test that built its own call got the default
     * verifier instead, which reads ~/.ssh/known_hosts - so it passed on a
     * developer machine that happened to have an entry and failed on a clean
     * runner with no such file, for a reason that had nothing to do with what
     * the test was about.
     */
    public static function connectWith(Authentication $authentication): SshResource {
        return connect(
            self::uri(),
            $authentication,
            LoggerTest::get(),
            hostKeyVerifier: new AcceptAnyHostKey()
        );
    }
}
