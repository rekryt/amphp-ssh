<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\Message;

/**
 * @internal
 */
interface BinaryPacketWriter {
    public function updateEncryption(Encryption $encryption, Mac $encryptMac): void;

    /**
     * Write one packet.
     *
     * Returning does NOT mean the packet reached the network: the underlying
     * stream accepts what fits and queues the rest for the event loop to
     * flush. Never treat a completed write as proof of delivery; close the
     * connection through the stream's own shutdown path so the queue drains.
     *
     * @throws \Amp\ByteStream\ClosedException If the connection is already closed.
     */
    public function write(Message|string $message): void;
}
