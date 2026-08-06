<?php declare(strict_types=1);

namespace Amp\Ssh\Encryption;

/**
 * AES in Galois/Counter Mode, as SSH uses it (RFC 5647).
 *
 * Implements Encryption and Decryption so that algorithm negotiation keeps
 * working unchanged, but crypt()/decrypt() are meaningless here: an AEAD
 * cipher cannot encrypt without also authenticating, so the transport takes
 * the AeadCipher path instead.
 *
 * The nonce is a 4-byte fixed field from key derivation followed by an 8-byte
 * invocation counter that advances once per packet. One instance therefore
 * belongs to exactly one direction of one connection.
 *
 * @internal
 */
final class AesGcm implements Encryption, Decryption, AeadCipher {
    private const TAG_LENGTH = 16;

    private const BLOCK_SIZE = 16;

    private const IV_LENGTH = 12;

    private const FIXED_LENGTH = 4;

    private int $keySize;

    private string $key = '';

    private string $fixed = '';

    private int $counter = 0;

    public function __construct(int $keySize = 128) {
        $this->keySize = $keySize;
    }

    public function getName(): string {
        // OpenSSH ships these under its own names; the RFC 5647 spelling
        // (AEAD_AES_128_GCM) is not what servers actually offer.
        return \sprintf('aes%d-gcm@openssh.com', $this->keySize);
    }

    public function getKeySize(): int {
        return \intdiv($this->keySize, 8);
    }

    public function getIvSize(): int {
        return self::IV_LENGTH;
    }

    public function getBlockSize(): int {
        return self::BLOCK_SIZE;
    }

    public function getTagLength(): int {
        return self::TAG_LENGTH;
    }

    public function reset(string $key, string $iv): void {
        $this->key = $key;
        $this->fixed = \substr($iv, 0, self::FIXED_LENGTH);

        // The counter half of the nonce starts from whatever key derivation
        // produced, exactly as OpenSSH does.
        $this->counter = (int) \unpack('J', \substr($iv, self::FIXED_LENGTH, 8))[1];
    }

    public function resetEncrypt(string $key, string $initIv): void {
        $this->reset($key, $initIv);
    }

    public function resetDecrypt(string $key, string $initIv): void {
        $this->reset($key, $initIv);
    }

    public function getLengthFieldSize(): int {
        return 4;
    }

    /**
     * The length travels in the clear here and is authenticated as associated
     * data, so reading it needs no key and no state.
     */
    public function decodeLength(int $sequenceNumber, string $lengthField): int {
        return \unpack('N', $lengthField)[1];
    }

    public function sealPacket(int $sequenceNumber, int $packetLength, string $plaintext): string {
        $associatedData = \pack('N', $packetLength);
        $tag = '';

        $ciphertext = \openssl_encrypt(
            $plaintext,
            $this->method(),
            $this->key,
            OPENSSL_RAW_DATA,
            $this->nonce(),
            $tag,
            $associatedData,
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Failed to encrypt packet with ' . $this->getName());
        }

        $this->advance();

        return $associatedData . $ciphertext . $tag;
    }

    public function openPacket(int $sequenceNumber, string $lengthField, string $ciphertext, string $tag): ?string {
        $plaintext = \openssl_decrypt(
            $ciphertext,
            $this->method(),
            $this->key,
            OPENSSL_RAW_DATA,
            $this->nonce(),
            $tag,
            $lengthField
        );

        $this->advance();

        return $plaintext === false ? null : $plaintext;
    }

    public function crypt(string $payload): string {
        throw new \LogicException(self::class . ' authenticates and encrypts together; use seal()');
    }

    public function decrypt(string $payload): string {
        throw new \LogicException(self::class . ' authenticates and encrypts together; use open()');
    }

    /**
     * @return self[]
     */
    public static function create(): array {
        return [
            new self(256),
            new self(128),
        ];
    }

    private function method(): string {
        return \sprintf('aes-%d-gcm', $this->keySize);
    }

    private function nonce(): string {
        return $this->fixed . \pack('J', $this->counter);
    }

    /**
     * Advances the invocation counter with exact 64 bit wraparound.
     *
     * The counter is unsigned on the wire but a signed int here, so half the
     * possible starting values come out of unpack() negative. Masking with
     * PHP_INT_MAX to avoid the float overflow at the top would clear the high
     * bit of exactly those - which produced a valid first packet and a bad tag
     * on the second. Two's complement already wraps correctly; only the single
     * step off PHP_INT_MAX needs help.
     */
    private function advance(): void {
        $this->counter = $this->counter === PHP_INT_MAX ? PHP_INT_MIN : $this->counter + 1;
    }
}
