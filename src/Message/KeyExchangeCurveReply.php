<?php declare(strict_types=1);

namespace Amp\Ssh\Message;

use function Amp\Ssh\Transport\read_byte;
use function Amp\Ssh\Transport\read_string;

/**
 * @internal
 */
final class KeyExchangeCurveReply implements Message {
    /** Full host key blob, exactly as it goes into the exchange hash. */
    public $hostKey;

    public $hostKeyFormat;

    public $fBytes;

    /** Full signature blob: the format name followed by the signature. */
    public $signature;

    public $signatureFormat;

    /** The signature itself, without the format name in front of it. */
    public $signatureBlob;

    public function encode(): string {
        throw new \RuntimeException('Not implemented');
    }

    public static function decode(string $payload) {
        read_byte($payload);

        $message = new static();

        // Read host key
        $fullKey = $message->hostKey = read_string($payload);
        $message->hostKeyFormat = read_string($fullKey);

        // Read fBytes
        $message->fBytes = read_string($payload);

        // Read signature
        $signature = $message->signature = read_string($payload);
        $message->signatureFormat = read_string($signature);
        $message->signatureBlob = read_string($signature);

        return $message;
    }

    public static function getNumber(): int {
        return self::SSH_MSG_KEX_ECDH_REPLY;
    }
}
