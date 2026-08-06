<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Cancellation;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\Debug;
use Amp\Ssh\Message\Message;
use Psr\Log\LoggerInterface;

/**
 * @internal
 */
final class LoggerHandler implements BinaryPacketHandler {
    private BinaryPacketHandler $handler;

    private LoggerInterface $logger;

    public function __construct(BinaryPacketHandler $handler, LoggerInterface $logger) {
        $this->handler = $handler;
        $this->logger = $logger;
    }

    public function updateDecryption(Decryption $decryption, Mac $decryptMac): void {
        $this->logger->debug(\sprintf('Decryption (server -> client) updated, cipher: %s, mac: %s', $decryption->getName(), $decryptMac->getName()));

        $this->handler->updateDecryption($decryption, $decryptMac);
    }

    public function updateEncryption(Encryption $encryption, Mac $encryptMac): void {
        $this->logger->debug(\sprintf('Encryption (client -> server) updated, cipher: %s, mac: %s', $encryption->getName(), $encryptMac->getName()));

        $this->handler->updateEncryption($encryption, $encryptMac);
    }

    public function read(?Cancellation $cancellation = null): Message|string|null {
        $packet = $this->handler->read($cancellation);

        if ($packet === null) {
            return null;
        }

        if ($packet instanceof Message) {
            $this->logger->debug(\sprintf('Receive %s packet', \get_class($packet)));
        } else {
            $type = \unpack('C', $packet)[1];
            $this->logger->warning(\sprintf('Unknown packet with number %s received', $type));
        }

        if ($packet instanceof Debug) {
            if ($packet->alwaysDisplay) {
                $this->logger->info(\sprintf('Debug received from server : %s', $packet->message));
            } else {
                $this->logger->debug(\sprintf('Debug received from server : %s', $packet->message));
            }
        }

        return $packet;
    }

    public function close(): void {
        $this->logger->debug('Shutting down ssh connection');

        $this->handler->close();
    }

    public function write(Message|string $message): void {
        if ($message instanceof Message) {
            $this->logger->debug(\sprintf('Sending %s packet', \get_class($message)));
        }

        $this->handler->write($message);
    }
}
