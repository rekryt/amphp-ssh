<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Cancellation;
use Amp\Socket\Socket;
use Amp\Ssh\Encryption;
use Amp\Ssh\Mac;
use Amp\Ssh\Message\Message;

/**
 * @internal
 */
final class PayloadReader implements BinaryPacketReader {
    private Encryption\Decryption $decryption;

    private Mac\Mac $decryptMac;

    private int $readSequenceNumber = 0;

    private string $decryptedBuffer = '';

    private Socket $socket;

    private string $cryptedBuffer;

    public function __construct(Socket $socket, string $buffer) {
        $this->cryptedBuffer = $buffer;
        $this->socket = $socket;
        $this->decryption = new Encryption\None();
        $this->decryptMac = new Mac\None();
    }

    public function updateDecryption(Encryption\Decryption $decryption, Mac\Mac $decryptMac): void {
        $this->decryption = $decryption;
        $this->decryptMac = $decryptMac;
    }

    public function read(?Cancellation $cancellation = null): Message|string|null {
        /*
        Each packet is in the following format:

          uint32    packet_length
          byte      padding_length
          byte[n1]  payload; n1 = packet_length - padding_length - 1
          byte[n2]  random padding; n2 = padding_length
          byte[m]   mac (Message Authentication Code - MAC); m = mac_length

          packet_length
             The length of the packet in bytes, not including 'mac' or the
             'packet_length' field itself.

          padding_length
             Length of 'random padding' (bytes).

          payload
             The useful contents of the packet.  If compression has been
             negotiated, this field is compressed.  Initially, compression
             MUST be "none".

          random padding
             Arbitrary-length padding, such that the total length of
             (packet_length || padding_length || payload || random padding)
             is a multiple of the cipher block size or 8, whichever is
             larger.  There MUST be at least four bytes of padding.  The
             padding SHOULD consist of random bytes.  The maximum amount of
             padding is 255 bytes.

          mac
             Message Authentication Code.  If message authentication has
             been negotiated, this field contains the MAC bytes.  Initially,
             the MAC algorithm MUST be "none".
         */
        if ($this->decryption instanceof Encryption\AeadCipher) {
            return $this->readAead($this->decryption, $cancellation);
        }

        $packetLengthRead = $this->doReadDecrypted(4, $cancellation);

        if ($packetLengthRead === null) {
            return null;
        }

        $packetLength = \unpack('N', $packetLengthRead)[1];
        $packet = $this->doReadDecrypted($packetLength, $cancellation);

        if ($packet === null) {
            return null;
        }

        $paddingLength = \unpack('C', $packet)[1];
        $payload = \substr($packet, 1, $packetLength - $paddingLength - 1);
        $padding = \substr($packet, $packetLength - $paddingLength);

        $mac = $this->doReadRaw($this->decryptMac->getLength(), $cancellation);

        if ($mac === null) {
            return null;
        }

        $computedMac = $this->decryptMac->hash(\pack(
            'NNCa*',
            $this->readSequenceNumber,
            $packetLength,
            $paddingLength,
            $payload . $padding
        ));

        if (!\hash_equals($computedMac, $mac)) {
            throw new \RuntimeException('Invalid mac');
        }

        $this->readSequenceNumber++;

        return $payload;
    }

    /**
     * Reads a packet protected by an AEAD cipher.
     *
     * The length arrives unencrypted and doubles as associated data, so there
     * is no decrypt-the-first-block dance; the tag that follows the ciphertext
     * covers both. A tag that does not check out is a failed integrity check,
     * the AEAD equivalent of a bad MAC.
     */
    private function readAead(Encryption\AeadCipher $cipher, ?Cancellation $cancellation): ?string {
        $lengthField = $this->doReadRaw($cipher->getLengthFieldSize(), $cancellation);

        if ($lengthField === null) {
            return null;
        }

        // How the length is carried differs between AEAD ciphers - in the
        // clear for GCM, encrypted under a second key for ChaCha20-Poly1305 -
        // so the cipher decides how to read it.
        $packetLength = $cipher->decodeLength($this->readSequenceNumber, $lengthField);

        $sealed = $this->doReadRaw($packetLength + $cipher->getTagLength(), $cancellation);

        if ($sealed === null) {
            return null;
        }

        $plaintext = $cipher->openPacket(
            $this->readSequenceNumber,
            $lengthField,
            \substr($sealed, 0, $packetLength),
            \substr($sealed, $packetLength)
        );

        if ($plaintext === null) {
            throw new \RuntimeException('Invalid mac');
        }

        $paddingLength = \unpack('C', $plaintext)[1];

        $this->readSequenceNumber++;

        return \substr($plaintext, 1, $packetLength - $paddingLength - 1);
    }

    private function doReadDecrypted(int $length, ?Cancellation $cancellation): ?string {
        while (\strlen($this->decryptedBuffer) < $length) {
            $rawRead = $this->doReadRaw($this->decryption->getBlockSize(), $cancellation);

            if ($rawRead === null) {
                return null;
            }

            $this->decryptedBuffer .= $this->decryption->decrypt($rawRead);
        }

        $read = \substr($this->decryptedBuffer, 0, $length);
        $this->decryptedBuffer = \substr($this->decryptedBuffer, $length);

        return $read;
    }

    private function doReadRaw(int $length, ?Cancellation $cancellation): ?string {
        while (\strlen($this->cryptedBuffer) < $length) {
            $read = $this->socket->read($cancellation);

            if ($read === null) {
                return null;
            }

            $this->cryptedBuffer .= $read;
        }

        $read = \substr($this->cryptedBuffer, 0, $length);
        $this->cryptedBuffer = \substr($this->cryptedBuffer, $length);

        return $read;
    }
}
