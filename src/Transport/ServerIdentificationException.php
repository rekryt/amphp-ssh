<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

/**
 * Thrown when the peer never identifies itself as an SSH server.
 *
 * An SSH connection opens with each side sending a line beginning with "SSH-".
 * A peer that hangs up first, or that answers with something else entirely, has
 * failed before authentication was ever attempted - which is why this is not an
 * authentication failure, however much it looks like one from the outside. A
 * firewall that accepts the connection and drops it, or a web server on the
 * port you meant to be sshd, both land here.
 */
final class ServerIdentificationException extends \RuntimeException {
    /**
     * Anything before the identification line is preamble, which the RFC allows
     * and does not bound. This is where we stop believing one is coming.
     */
    public const MAX_PREAMBLE_BYTES = 65536;

    public static function connectionClosed(): self {
        return new self('The peer closed the connection before sending an SSH identification string');
    }

    public static function preambleTooLong(): self {
        return new self(\sprintf(
            'The peer sent %d bytes without an SSH identification string; it does not appear to be an SSH server',
            self::MAX_PREAMBLE_BYTES
        ));
    }
}
