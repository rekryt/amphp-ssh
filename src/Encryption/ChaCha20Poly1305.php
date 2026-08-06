<?php declare(strict_types=1);

namespace Amp\Ssh\Encryption;

use ParagonIE_Sodium_Core_Poly1305;

/**
 * chacha20-poly1305@openssh.com.
 *
 * OpenSSH's own construction, which is not the RFC 8439 AEAD despite using the
 * same two primitives. The 64 byte key is two independent ChaCha20 keys: the
 * first encrypts the payload, the second encrypts the packet length so that a
 * passive observer cannot see message boundaries. Poly1305 then covers the
 * encrypted length together with the encrypted payload, keyed from the first
 * 32 bytes of the payload keystream at counter 0.
 *
 * Two details make this easy to get wrong:
 *
 *  - the ChaCha20 variant is the original one, with a 64 bit nonce and a 64
 *    bit counter, not the IETF split of 96 and 32. OpenSSL's `chacha20` takes
 *    all sixteen IV bytes as state words 12..15, so the original layout is
 *    reached by putting the counter in the first eight bytes and the nonce in
 *    the last eight;
 *  - the nonce is the SSH packet sequence number, big endian, so the cipher
 *    holds no counter of its own.
 *
 * @internal
 */
final class ChaCha20Poly1305 implements Encryption, Decryption, AeadCipher {
    public const NAME = 'chacha20-poly1305@openssh.com';

    private const TAG_LENGTH = 16;

    private const BLOCK_SIZE = 8;

    private const KEY_LENGTH = 64;

    private const LENGTH_FIELD_SIZE = 4;

    /** Encrypts the payload and derives the Poly1305 key. */
    private string $payloadKey = '';

    /** Encrypts the packet length field only. */
    private string $lengthKey = '';

    public function getName(): string {
        return self::NAME;
    }

    public function getKeySize(): int {
        return self::KEY_LENGTH;
    }

    public function getIvSize(): int {
        // The sequence number is the nonce, so no IV is derived.
        return 0;
    }

    public function getBlockSize(): int {
        return self::BLOCK_SIZE;
    }

    public function getTagLength(): int {
        return self::TAG_LENGTH;
    }

    public function getLengthFieldSize(): int {
        return self::LENGTH_FIELD_SIZE;
    }

    public function reset(string $key, string $iv): void {
        if (\strlen($key) !== self::KEY_LENGTH) {
            throw new \RuntimeException(\sprintf('%s needs a %d byte key', self::NAME, self::KEY_LENGTH));
        }

        $this->payloadKey = \substr($key, 0, 32);
        $this->lengthKey = \substr($key, 32, 32);
    }

    public function resetEncrypt(string $key, string $initIv): void {
        $this->reset($key, $initIv);
    }

    public function resetDecrypt(string $key, string $initIv): void {
        $this->reset($key, $initIv);
    }

    public function decodeLength(int $sequenceNumber, string $lengthField): int {
        return \unpack('N', $this->lengthKeystream($sequenceNumber, $lengthField))[1];
    }

    public function sealPacket(int $sequenceNumber, int $packetLength, string $plaintext): string {
        $encryptedLength = $this->lengthKeystream($sequenceNumber, \pack('N', $packetLength));

        $ciphertext = $this->chacha20($this->payloadKey, $sequenceNumber, 1, $plaintext);

        $tag = ParagonIE_Sodium_Core_Poly1305::onetimeauth(
            $encryptedLength . $ciphertext,
            $this->polyKey($sequenceNumber)
        );

        return $encryptedLength . $ciphertext . $tag;
    }

    public function openPacket(int $sequenceNumber, string $lengthField, string $ciphertext, string $tag): ?string {
        $expected = ParagonIE_Sodium_Core_Poly1305::onetimeauth(
            $lengthField . $ciphertext,
            $this->polyKey($sequenceNumber)
        );

        // The tag covers the encrypted bytes, so it can and must be checked
        // before anything is decrypted.
        if (!\hash_equals($expected, $tag)) {
            return null;
        }

        return $this->chacha20($this->payloadKey, $sequenceNumber, 1, $ciphertext);
    }

    public function crypt(string $payload): string {
        throw new \LogicException(self::class . ' authenticates and encrypts together; use sealPacket()');
    }

    public function decrypt(string $payload): string {
        throw new \LogicException(self::class . ' authenticates and encrypts together; use openPacket()');
    }

    /**
     * XORs the length field with the separate length keystream.
     *
     * Symmetric, so the same call both encrypts and decrypts it.
     */
    private function lengthKeystream(int $sequenceNumber, string $lengthField): string {
        return $this->chacha20($this->lengthKey, $sequenceNumber, 0, $lengthField);
    }

    /**
     * Poly1305 is keyed from the first 32 bytes of the payload keystream at
     * counter 0, which is why the payload itself starts at counter 1.
     */
    private function polyKey(int $sequenceNumber): string {
        return \substr(
            $this->chacha20($this->payloadKey, $sequenceNumber, 0, \str_repeat("\0", 32)),
            0,
            32
        );
    }

    private function chacha20(string $key, int $sequenceNumber, int $counter, string $data): string {
        if ($data === '') {
            return '';
        }

        // State words 12..15: a 64 bit little endian counter followed by the
        // sequence number as a 64 bit big endian nonce.
        $iv = \pack('P', $counter) . \pack('J', $sequenceNumber);

        $result = \openssl_encrypt($data, 'chacha20', $key, OPENSSL_RAW_DATA, $iv);

        if ($result === false) {
            throw new \RuntimeException('Failed to run ChaCha20; is ext-openssl built with it?');
        }

        return $result;
    }
}
