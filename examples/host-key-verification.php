<?php declare(strict_types=1);

// Deciding whether the server on the other end is the one you meant to reach.
//
// Two separate checks are involved, and either one alone is worthless. The
// library always verifies the host key signature, which proves the peer holds
// the key it presented. That says nothing about whether the key belongs to
// this host - which is what a HostKeyVerifier decides.
//
// connect() uses KnownHosts by default, so an unknown host is an error. The
// alternatives, in descending order of how much they protect you:
//
//   new KnownHosts()                            ~/.ssh/known_hosts, the default
//   new KnownHosts('/etc/ssh/ssh_known_hosts')  a file you manage centrally
//   new KnownHosts(null, false)                 only complain if a known key changed
//   new AcceptAnyHostKey()                      no protection against interception
//
// A pinned fingerprint, shown below, suits deployments where the expected key
// is known in advance and belongs in configuration rather than in a file that
// grows on its own.

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\HostKey\HostKeyVerificationException;
use Amp\Ssh\HostKey\HostKeyVerifier;
use Amp\Ssh\Process;

/**
 * The fingerprint in the form ssh-keygen prints it.
 *
 * Identical to `ssh-keygen -lf` output, so the value can be checked against
 * whatever the server's administrator published.
 */
function fingerprint(string $key): string {
    return 'SHA256:' . \rtrim(\base64_encode(\hash('sha256', $key, true)), '=');
}

// Step 1: learn the key. Accepting whatever the server offers is exactly the
// window in which an interception would be recorded as legitimate, which is
// why this belongs in a one-off setup step over a channel you trust, not in
// the code that connects every day.
$recorder = new class implements HostKeyVerifier {
    public string $format = '';

    public string $key = '';

    public function verify(string $host, int $port, string $format, string $key): void {
        $this->format = $format;
        $this->key = $key;
    }
};

$ssh = connect($target, new PublicKey($username, $keyPath), hostKeyVerifier: $recorder);
$ssh->close();

$expected = fingerprint($recorder->key);

\printf('%s offers a %s key: %s%s', $target, $recorder->format, $expected, PHP_EOL);

/**
 * A verifier that accepts one fingerprint and refuses everything else.
 */
function pinnedTo(string $expected): HostKeyVerifier {
    return new class($expected) implements HostKeyVerifier {
        public function __construct(private string $expected) {
        }

        public function verify(string $host, int $port, string $format, string $key): void {
            $actual = fingerprint($key);

            // Constant time, so a comparison cannot be timed to learn the
            // expected value one character at a time.
            if (!\hash_equals($this->expected, $actual)) {
                throw new HostKeyVerificationException(\sprintf(
                    'Host key mismatch for %s: expected %s, got %s.',
                    $host,
                    $this->expected,
                    $actual
                ));
            }
        }
    };
}

// Step 2: from now on, accept that key and nothing else.
$ssh = connect($target, new PublicKey($username, $keyPath), hostKeyVerifier: pinnedTo($expected));

$process = new Process($ssh, 'echo connected to the expected host');
$process->start();

echo ByteStream\buffer($process->getStdout());
$process->join();
$ssh->close();

// Step 3: a key that does not match is refused before authentication, so no
// password and no key signature is ever offered to the wrong server.
try {
    connect(
        $target,
        new PublicKey($username, $keyPath),
        hostKeyVerifier: pinnedTo('SHA256:' . \str_repeat('A', 43))
    );

    echo 'This line is unreachable.', PHP_EOL;
} catch (HostKeyVerificationException $exception) {
    echo 'Refused, as it should be: ', $exception->getMessage(), PHP_EOL;
}
