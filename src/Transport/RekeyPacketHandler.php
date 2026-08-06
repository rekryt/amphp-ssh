<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Cancellation;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\Message;

/**
 * Lets a key re-exchange read the packets it needs while the session runs on.
 *
 * A rekey happens in the middle of a live connection, and RFC 4253 section 7.1
 * only stops each side from *sending* non-transport messages once it has sent
 * KEXINIT: data already in flight keeps arriving until NEWKEYS. The key
 * exchange code expects the next packet to be its own, so anything else has to
 * be handed back to the normal dispatcher instead of being mistaken for a
 * malformed reply.
 *
 * @internal
 */
final class RekeyPacketHandler implements BinaryPacketHandler {
    /** Everything below this number belongs to the transport layer. */
    private const TRANSPORT_LAYER_LIMIT = 50;

    private BinaryPacketHandler $handler;

    /** @var \Closure(Message):void */
    private \Closure $route;

    /**
     * @param \Closure(Message):void $route Receives packets that are not part
     *                                      of the key exchange.
     */
    public function __construct(BinaryPacketHandler $handler, \Closure $route) {
        $this->handler = $handler;
        $this->route = $route;
    }

    public function read(?Cancellation $cancellation = null): Message|string|null {
        while (true) {
            $packet = $this->handler->read($cancellation);

            if ($packet === null || !$packet instanceof Message) {
                return $packet;
            }

            if ($packet::getNumber() < self::TRANSPORT_LAYER_LIMIT) {
                return $packet;
            }

            ($this->route)($packet);
        }
    }

    public function write(Message|string $message): void {
        $this->handler->write($message);
    }

    public function updateDecryption(Decryption $decryption, Mac $decryptMac): void {
        $this->handler->updateDecryption($decryption, $decryptMac);
    }

    public function updateEncryption(Encryption $encryption, Mac $encryptMac): void {
        $this->handler->updateEncryption($encryption, $encryptMac);
    }

    public function close(): void {
        $this->handler->close();
    }
}
