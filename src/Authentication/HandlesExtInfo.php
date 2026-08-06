<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Cancellation;
use Amp\Ssh\Message\ExtInfo;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Transport\BinaryPacketHandler;

/**
 * Transparent handling of SSH_MSG_EXT_INFO during authentication.
 *
 * A server that supports RFC 8308 sends EXT_INFO right after NEWKEYS, which
 * means it lands in the middle of the authentication exchange - typically
 * where SERVICE_ACCEPT is expected. It has to be consumed there rather than
 * mistaken for the reply we were waiting for.
 *
 * @internal
 */
trait HandlesExtInfo {
    /** @var string[] */
    private array $serverSignatureAlgorithms = [];

    /**
     * Reads the next message, absorbing any extension information on the way.
     */
    private function readMessage(BinaryPacketHandler $handler, ?Cancellation $cancellation): Message|string|null {
        while (true) {
            $packet = $handler->read($cancellation);

            if (!$packet instanceof ExtInfo) {
                return $packet;
            }

            $this->serverSignatureAlgorithms = $packet->getServerSignatureAlgorithms();
        }
    }

}
