<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Cancellation;
use Amp\Socket\Socket;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\Message;

/**
 * @internal
 */
final class PayloadHandler implements BinaryPacketHandler {
    private PayloadReader $reader;

    private PayloadWriter $writer;

    private Socket $socket;

    public function __construct(Socket $socket, string $buffer) {
        $this->reader = new PayloadReader($socket, $buffer);
        $this->writer = new PayloadWriter($socket);
        $this->socket = $socket;
    }

    public function updateDecryption(Decryption $decryption, Mac $decryptMac): void {
        $this->reader->updateDecryption($decryption, $decryptMac);
    }

    public function updateEncryption(Encryption $encryption, Mac $encryptMac): void {
        $this->writer->updateEncryption($encryption, $encryptMac);
    }

    public function read(?Cancellation $cancellation = null): Message|string|null {
        return $this->reader->read($cancellation);
    }

    public function write(Message|string $message): void {
        $this->writer->write($message);
    }

    public function close(): void {
        $this->socket->close();
    }
}
