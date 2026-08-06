<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Socket\Socket;
use Amp\Ssh\Encryption;
use Amp\Ssh\Mac;
use Amp\Ssh\Message\Message;

/**
 * @internal
 */
final class PayloadWriter implements BinaryPacketWriter {
    private Encryption\Encryption $encryption;

    private Mac\Mac $encryptMac;

    private int $writeSequenceNumber = 0;

    private Socket $socket;

    public function __construct(Socket $socket) {
        $this->socket = $socket;
        $this->encryption = new Encryption\None();
        $this->encryptMac = new Mac\None();
    }

    public function updateEncryption(Encryption\Encryption $encryption, Mac\Mac $encryptMac): void {
        $this->encryption = $encryption;
        $this->encryptMac = $encryptMac;
    }

    public function write(Message|string $message): void {
        $payload = $message instanceof Message ? $message->encode() : $message;

        if ($this->encryption instanceof Encryption\AeadCipher) {
            $this->writeAead($payload, $this->encryption);

            return;
        }

        $length = 4 + 1 + \strlen($payload);
        $paddingLength = $this->encryption->getBlockSize() - ($length % $this->encryption->getBlockSize());
        $paddingLength += $paddingLength < 4 ? $this->encryption->getBlockSize() : 0;

        $padding = \random_bytes($paddingLength);
        $packetLength = \strlen($payload) + $paddingLength + 1;
        $packet = \pack('NCa*a*', $packetLength, $paddingLength, $payload, $padding);
        $mac = $this->encryptMac->hash(\pack('Na*', $this->writeSequenceNumber, $packet));
        $cipher = $this->encryption->crypt($packet);
        $cipher .= $mac;

        $this->writeSequenceNumber++;

        $this->socket->write($cipher);
    }

    /**
     * Writes a packet under an AEAD cipher.
     *
     * The layout differs from the classic one: packet_length stays in the
     * clear and is fed in as associated data, only padding_length, payload and
     * padding are encrypted, and the tag replaces the separate MAC. The
     * encrypted run - not the whole packet - is what has to stay aligned to
     * the block size.
     */
    private function writeAead(string $payload, Encryption\AeadCipher $cipher): void {
        $blockSize = $cipher->getBlockSize();

        $paddingLength = $blockSize - ((1 + \strlen($payload)) % $blockSize);

        if ($paddingLength < 4) {
            $paddingLength += $blockSize;
        }

        $packetLength = 1 + \strlen($payload) + $paddingLength;

        $plaintext = \pack('Ca*a*', $paddingLength, $payload, \random_bytes($paddingLength));

        // The cipher returns the whole packet, length field included: only it
        // knows whether that field goes out in the clear or encrypted.
        $packet = $cipher->sealPacket($this->writeSequenceNumber, $packetLength, $plaintext);

        $this->writeSequenceNumber++;

        $this->socket->write($packet);
    }
}
