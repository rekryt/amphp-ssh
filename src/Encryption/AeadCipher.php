<?php declare(strict_types=1);

namespace Amp\Ssh\Encryption;

/**
 * A cipher that authenticates as well as encrypts.
 *
 * These change the shape of the binary packet rather than just the algorithm
 * inside it, and they do not all change it the same way: AES-GCM leaves the
 * packet length in the clear and authenticates it as associated data, while
 * chacha20-poly1305@openssh.com encrypts it under a separate key. Framing is
 * therefore the cipher's business, not the transport's - hence sealPacket()
 * and openPacket() rather than a plain encrypt/decrypt pair.
 *
 * The negotiated MAC algorithm is ignored for all of them; RFC 5647 calls it
 * implicit.
 *
 * @internal
 */
interface AeadCipher {
    public function getName(): string;

    /** Key length in bytes. */
    public function getKeySize(): int;

    /** Nonce length in bytes; zero when the cipher derives it from the sequence number. */
    public function getIvSize(): int;

    /** Alignment the encrypted portion of a packet must respect. */
    public function getBlockSize(): int;

    public function getTagLength(): int;

    /** Size of the packet length field on the wire. */
    public function getLengthFieldSize(): int;

    public function reset(string $key, string $iv): void;

    /**
     * Reads the packet length out of its on-wire form.
     *
     * Called before the rest of the packet has arrived, so it must not disturb
     * any state the matching openPacket() call still needs.
     */
    public function decodeLength(int $sequenceNumber, string $lengthField): int;

    /**
     * @return string The complete packet: length field, ciphertext and tag.
     */
    public function sealPacket(int $sequenceNumber, int $packetLength, string $plaintext): string;

    /**
     * @param string $lengthField The length field exactly as it arrived.
     *
     * @return string|null Plaintext, or null when authentication fails.
     */
    public function openPacket(int $sequenceNumber, string $lengthField, string $ciphertext, string $tag): ?string;
}
