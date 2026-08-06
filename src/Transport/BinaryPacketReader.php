<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Cancellation;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\Message;

/**
 * @internal
 */
interface BinaryPacketReader {
    public function updateDecryption(Decryption $decryption, Mac $decryptMac): void;

    /**
     * Read one packet, blocking the current fiber until one is available.
     *
     * Returns null once the peer has closed the connection. The lower layers
     * return the raw payload; only MessageHandler turns it into a Message, and
     * even then an unregistered message number stays a raw string.
     *
     * Cancelling only detaches this caller: the connection stays open and the
     * packet, if it arrives, is still consumed by the next read.
     */
    public function read(?Cancellation $cancellation = null): Message|string|null;
}
