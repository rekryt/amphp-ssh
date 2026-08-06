<?php declare(strict_types=1);

namespace Amp\Ssh\HostKey;

/**
 * Decides whether the host key a server presented is the one we expected.
 *
 * The signature check that precedes this only proves the peer holds the key it
 * showed us; it says nothing about whether that peer is the host we meant to
 * reach. Answering that is the job of an implementation of this interface.
 */
interface HostKeyVerifier {
    /**
     * @param string $host    Host as given to connect().
     * @param int    $port    Port as given to connect().
     * @param string $format  Key format, e.g. ssh-rsa or ssh-ed25519.
     * @param string $key     Raw host key blob, as sent by the server.
     *
     * @throws HostKeyVerificationException When the key is not trusted.
     */
    public function verify(string $host, int $port, string $format, string $key): void;
}
