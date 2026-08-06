<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Encryption;

use Amp\Ssh\Encryption\AeadCipher;
use Amp\Ssh\Encryption\AesGcm;
use PHPUnit\Framework\TestCase;

/**
 * AES-GCM, the AEAD cipher SSH uses under the aes*-gcm@openssh.com names.
 *
 * Unlike chacha20-poly1305@openssh.com this one leaves the packet length in
 * the clear and authenticates it as associated data.
 */
class AesGcmTest extends TestCase {
    /**
     * @return AesGcm[] Sender and receiver sharing one key and nonce.
     */
    private function pair(int $bits, string $iv): array {
        $key = \random_bytes(\intdiv($bits, 8));

        $sender = new AesGcm($bits);
        $sender->reset($key, $iv);

        $receiver = new AesGcm($bits);
        $receiver->reset($key, $iv);

        return [$sender, $receiver];
    }

    /**
     * Splits a sealed packet into the pieces the reader works with.
     *
     * @return array{0: string, 1: string, 2: string} Length field, ciphertext, tag.
     */
    private function split(string $packet): array {
        return [
            \substr($packet, 0, 4),
            \substr($packet, 4, -16),
            \substr($packet, -16),
        ];
    }

    public function provideKeySizes(): iterable {
        yield '128' => [128];
        yield '256' => [256];
    }

    /**
     * @dataProvider provideKeySizes
     */
    public function testRoundTrip(int $bits) {
        [$sender, $receiver] = $this->pair($bits, \random_bytes(12));

        $plaintext = \random_bytes(64);
        $packet = $sender->sealPacket(0, \strlen($plaintext), $plaintext);

        [$lengthField, $ciphertext, $tag] = $this->split($packet);

        self::assertSame(\strlen($plaintext), $receiver->decodeLength(0, $lengthField));
        self::assertSame($plaintext, $receiver->openPacket(0, $lengthField, $ciphertext, $tag));
    }

    /**
     * The length is associated data here, not ciphertext.
     */
    public function testPacketLengthTravelsInTheClear() {
        [$sender] = $this->pair(256, \random_bytes(12));

        $packet = $sender->sealPacket(0, 64, \random_bytes(64));

        self::assertSame(\pack('N', 64), \substr($packet, 0, 4));
    }

    /**
     * The nonce advances once per packet, so a second packet must still open.
     *
     * This is what caught a broken counter: masking it to avoid an integer
     * overflow cleared its high bit, which let the first packet through and
     * made every one after it fail.
     */
    public function testManyPacketsInSequence() {
        [$sender, $receiver] = $this->pair(256, \random_bytes(12));

        for ($i = 0; $i < 32; ++$i) {
            $plaintext = \random_bytes(16 + $i);
            $packet = $sender->sealPacket($i, \strlen($plaintext), $plaintext);

            [$lengthField, $ciphertext, $tag] = $this->split($packet);

            self::assertSame(
                $plaintext,
                $receiver->openPacket($i, $lengthField, $ciphertext, $tag),
                \sprintf('Packet %d must open', $i)
            );
        }
    }

    /**
     * A counter whose top bit is set is exactly the case the broken
     * implementation mishandled.
     */
    public function testCounterStartingWithTheHighBitSet() {
        $iv = \random_bytes(4) . "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFD";

        [$sender, $receiver] = $this->pair(256, $iv);

        for ($i = 0; $i < 6; ++$i) {
            $plaintext = \random_bytes(32);
            $packet = $sender->sealPacket($i, 32, $plaintext);

            [$lengthField, $ciphertext, $tag] = $this->split($packet);

            self::assertSame(
                $plaintext,
                $receiver->openPacket($i, $lengthField, $ciphertext, $tag),
                \sprintf('Packet %d must open across the counter wrap', $i)
            );
        }
    }

    public function testTamperedCiphertextIsRejected() {
        [$sender, $receiver] = $this->pair(256, \random_bytes(12));

        $packet = $sender->sealPacket(0, 32, \random_bytes(32));
        [$lengthField, $ciphertext, $tag] = $this->split($packet);

        $ciphertext[0] = $ciphertext[0] === "\x00" ? "\x01" : "\x00";

        self::assertNull($receiver->openPacket(0, $lengthField, $ciphertext, $tag));
    }

    /**
     * The packet length travels in the clear, so it has to be authenticated as
     * associated data; otherwise it could be rewritten in transit.
     */
    public function testTamperedLengthIsRejected() {
        [$sender, $receiver] = $this->pair(256, \random_bytes(12));

        $packet = $sender->sealPacket(0, 32, \random_bytes(32));
        [, $ciphertext, $tag] = $this->split($packet);

        self::assertNull($receiver->openPacket(0, \pack('N', 33), $ciphertext, $tag));
    }

    public function testNames() {
        self::assertSame('aes128-gcm@openssh.com', (new AesGcm(128))->getName());
        self::assertSame('aes256-gcm@openssh.com', (new AesGcm(256))->getName());
    }

    /**
     * The nonce is 12 bytes even though the block is 16; deriving the block
     * size worth of key material would produce the wrong nonce.
     */
    public function testNonceIsShorterThanTheBlock() {
        $cipher = new AesGcm(256);

        self::assertSame(12, $cipher->getIvSize());
        self::assertSame(16, $cipher->getBlockSize());
        self::assertSame(16, $cipher->getTagLength());
        self::assertSame(32, $cipher->getKeySize());
        self::assertSame(4, $cipher->getLengthFieldSize());
    }

    public function testItIsRecognisedAsAead() {
        self::assertInstanceOf(AeadCipher::class, new AesGcm(256));
    }

    /**
     * Encrypting without authenticating is not a thing an AEAD cipher can do,
     * so the classic entry points must refuse rather than quietly misbehave.
     */
    public function testBlockCipherEntryPointsRefuse() {
        $this->expectException(\LogicException::class);

        (new AesGcm(256))->crypt('data');
    }
}
