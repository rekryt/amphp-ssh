<?php declare(strict_types=1);

namespace Amp\Ssh\KeyExchange;

use Amp\Cancellation;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Transport\BinaryPacketHandler;

/**
 * @internal
 */
interface KeyExchange {
    public function getName(): string;

    /**
     * Run the key exchange and return the shared secret together with both
     * halves of the exchange, which the caller needs verbatim to compute the
     * exchange hash.
     *
     * Cancelling leaves the connection half-negotiated and therefore unusable;
     * the caller is expected to close it rather than try to recover.
     *
     * @return array{0: string, 1: Message, 2: Message} Shared secret, message
     *                                                  sent, message received.
     */
    public function exchange(BinaryPacketHandler $handler, ?Cancellation $cancellation = null): array;

    public function hash(string $payload): string;

    public function getEBytes(Message $message): string;

    public function getFBytes(Message $message): string;

    public function getHostKey(Message $message): string;
}
