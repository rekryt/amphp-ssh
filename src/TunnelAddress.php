<?php declare(strict_types=1);

namespace Amp\Ssh;

use Amp\Socket\SocketAddress;
use Amp\Socket\SocketAddressType;

/**
 * The far end of a tunnel, named the way it was asked for.
 *
 * Amp\Socket\InternetAddress cannot hold this, because it requires a literal
 * IP address - and the usual reason to open a tunnel is to reach a name that
 * only resolves on the far side of the connection. Tunnel returns an
 * InternetAddress where the host really is an address and one of these
 * otherwise, so code that expects the former is not surprised by a hostname.
 */
final class TunnelAddress implements SocketAddress {
    private string $host;

    private int $port;

    public function __construct(string $host, int $port) {
        $this->host = $host;
        $this->port = $port;
    }

    public function getHost(): string {
        return $this->host;
    }

    public function getPort(): int {
        return $this->port;
    }

    public function toString(): string {
        return \sprintf('%s:%d', $this->host, $this->port);
    }

    public function __toString(): string {
        return $this->toString();
    }

    public function getType(): SocketAddressType {
        return SocketAddressType::Internet;
    }
}
