<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

/**
 * Thrown when a packet ends before a field it claims to contain.
 *
 * This covers both a payload that is simply too short for the field being read
 * and a length prefix that points past the end of the packet. Without it the
 * readers would either raise a TypeError from a failed unpack() or, worse,
 * silently return a shortened value and let a corrupt packet through.
 */
final class TruncatedPacketException extends \RuntimeException {
    public static function forField(string $field, int $required, int $available): self {
        return new self(\sprintf(
            'Truncated packet: reading %s requires %d byte(s), %d available',
            $field,
            $required,
            $available
        ));
    }
}
