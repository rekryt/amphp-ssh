<?php declare(strict_types=1);

namespace Amp\Ssh\KeyExchange;

/**
 * Encodes a big integer the way RFC 4251 defines an mpint.
 *
 * There are two rules and only one of them used to be applied. A value whose
 * top bit is set needs a zero byte in front so that it is not read as
 * negative - and leading zero bytes that are not needed for that MUST NOT be
 * sent.
 *
 * Keeping them made the exchange hash disagree with the server's whenever the
 * shared secret happened to begin with a zero byte, which is about one
 * connection in 256 and presented itself as a host key signature that was
 * suddenly invalid.
 */
function twos_compliment(string $data): string {
    // A zero has no bytes at all in this encoding.
    $data = \ltrim($data, "\x00");

    if ($data === '') {
        return '';
    }

    return (\ord($data[0]) & 0x80) !== 0 ? "\x00" . $data : $data;
}
