<?php declare(strict_types=1);

namespace Amp\Ssh\Message;

use function Amp\Ssh\Transport\read_byte;
use function Amp\Ssh\Transport\read_string;
use function Amp\Ssh\Transport\read_uint32;

/**
 * SSH_MSG_EXT_INFO, the extension negotiation message of RFC 8308.
 *
 * A server only sends this when the client advertised "ext-info-c" among its
 * key exchange algorithms. The extension worth having is "server-sig-algs":
 * without it there is no way to know whether a server that refuses ssh-rsa
 * would accept an RSA key signed with SHA-2 instead.
 *
 * @internal
 */
final class ExtInfo implements Message {
    /** @var array<string, string> */
    public array $extensions = [];

    public function encode(): string {
        throw new \RuntimeException('Not implemented');
    }

    public static function decode(string $payload) {
        read_byte($payload);

        $message = new static();
        $count = read_uint32($payload);

        for ($i = 0; $i < $count; ++$i) {
            $name = read_string($payload);
            $message->extensions[$name] = read_string($payload);
        }

        return $message;
    }

    /**
     * Signature algorithms the server is willing to accept for publickey auth.
     *
     * @return string[] Empty when the server did not advertise any.
     */
    public function getServerSignatureAlgorithms(): array {
        $value = $this->extensions['server-sig-algs'] ?? '';

        if ($value === '') {
            return [];
        }

        return \explode(',', $value);
    }

    public static function getNumber(): int {
        return self::SSH_MSG_EXT_INFO;
    }
}
