<?php declare(strict_types=1);

namespace Amp\Ssh\HostKey;

/**
 * Accepts whatever host key the server presents.
 *
 * This defeats the point of host key checking: an attacker who can intercept
 * the connection can present a key of their own, sign the exchange with it,
 * and be believed. Use it only where the channel is already trusted by other
 * means - a test container, a loopback socket - and never as a way to silence
 * a verification failure against a real host.
 *
 * It exists as a named class precisely so that turning verification off has to
 * be written down and shows up in review, rather than being the default.
 */
final class AcceptAnyHostKey implements HostKeyVerifier {
    public function verify(string $host, int $port, string $format, string $key): void {
    }
}
