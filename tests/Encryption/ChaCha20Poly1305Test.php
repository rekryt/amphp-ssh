<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Encryption;

use Amp\Ssh\Encryption\AeadCipher;
use Amp\Ssh\Encryption\ChaCha20Poly1305;
use ParagonIE_Sodium_Core_Poly1305;
use PHPUnit\Framework\TestCase;

/**
 * chacha20-poly1305@openssh.com.
 *
 * OpenSSH's construction rather than the RFC 8439 AEAD: two independent keys,
 * an encrypted packet length, and Poly1305 over the encrypted bytes.
 */
class ChaCha20Poly1305Test extends TestCase {
    /**
     * @return ChaCha20Poly1305[] Sender and receiver sharing one key.
     */
    private function pair(): array {
        $key = \random_bytes(64);

        $sender = new ChaCha20Poly1305();
        $sender->reset($key, '');

        $receiver = new ChaCha20Poly1305();
        $receiver->reset($key, '');

        return [$sender, $receiver];
    }

    public function testRoundTrip() {
        [$sender, $receiver] = $this->pair();

        $plaintext = \random_bytes(120);
        $packet = $sender->sealPacket(7, \strlen($plaintext), $plaintext);

        $lengthField = \substr($packet, 0, 4);

        self::assertSame(\strlen($plaintext), $receiver->decodeLength(7, $lengthField));

        $body = \substr($packet, 4, -16);
        $tag = \substr($packet, -16);

        self::assertSame($plaintext, $receiver->openPacket(7, $lengthField, $body, $tag));
    }

    /**
     * Hiding message boundaries is the reason this cipher exists; a plaintext
     * length field would defeat it.
     */
    public function testPacketLengthIsEncrypted() {
        [$sender] = $this->pair();

        $plaintext = \random_bytes(64);
        $packet = $sender->sealPacket(0, \strlen($plaintext), $plaintext);

        self::assertNotSame(
            \pack('N', \strlen($plaintext)),
            \substr($packet, 0, 4),
            'The length field must not appear in the clear'
        );
    }

    /**
     * The sequence number is the nonce, so the same plaintext under the same
     * key must not produce the same bytes twice.
     */
    public function testSequenceNumberChangesTheCiphertext() {
        [$sender] = $this->pair();

        $plaintext = \str_repeat('a', 64);

        self::assertNotSame(
            $sender->sealPacket(1, 64, $plaintext),
            $sender->sealPacket(2, 64, $plaintext)
        );
    }

    public function testOpeningWithTheWrongSequenceNumberFails() {
        [$sender, $receiver] = $this->pair();

        $plaintext = \random_bytes(48);
        $packet = $sender->sealPacket(5, 48, $plaintext);

        self::assertNull($receiver->openPacket(
            6,
            \substr($packet, 0, 4),
            \substr($packet, 4, -16),
            \substr($packet, -16)
        ));
    }

    public function testTamperedCiphertextIsRejected() {
        [$sender, $receiver] = $this->pair();

        $packet = $sender->sealPacket(0, 48, \random_bytes(48));

        $body = \substr($packet, 4, -16);
        $body[0] = $body[0] === "\x00" ? "\x01" : "\x00";

        self::assertNull($receiver->openPacket(0, \substr($packet, 0, 4), $body, \substr($packet, -16)));
    }

    public function testTamperedLengthIsRejected() {
        [$sender, $receiver] = $this->pair();

        $packet = $sender->sealPacket(0, 48, \random_bytes(48));

        $lengthField = \substr($packet, 0, 4);
        $lengthField[3] = $lengthField[3] === "\x00" ? "\x01" : "\x00";

        self::assertNull($receiver->openPacket(0, $lengthField, \substr($packet, 4, -16), \substr($packet, -16)));
    }

    public function testManyPacketsInSequence() {
        [$sender, $receiver] = $this->pair();

        for ($sequence = 0; $sequence < 32; ++$sequence) {
            $plaintext = \random_bytes(8 + $sequence);
            $packet = $sender->sealPacket($sequence, \strlen($plaintext), $plaintext);

            self::assertSame(\strlen($plaintext), $receiver->decodeLength($sequence, \substr($packet, 0, 4)));
            self::assertSame($plaintext, $receiver->openPacket(
                $sequence,
                \substr($packet, 0, 4),
                \substr($packet, 4, -16),
                \substr($packet, -16)
            ));
        }
    }

    /**
     * The two halves of the key must not be interchangeable: swapping them has
     * to break both the length and the payload.
     */
    public function testKeyHalvesAreNotInterchangeable() {
        $key = \random_bytes(64);

        $sender = new ChaCha20Poly1305();
        $sender->reset($key, '');

        $swapped = new ChaCha20Poly1305();
        $swapped->reset(\substr($key, 32) . \substr($key, 0, 32), '');

        $packet = $sender->sealPacket(0, 32, \random_bytes(32));

        self::assertNull($swapped->openPacket(
            0,
            \substr($packet, 0, 4),
            \substr($packet, 4, -16),
            \substr($packet, -16)
        ));
    }

    /**
     * Poly1305 covers the encrypted length together with the encrypted
     * payload, keyed from the payload keystream at counter 0.
     */
    public function testTagMatchesTheDocumentedConstruction() {
        $key = \random_bytes(64);

        $cipher = new ChaCha20Poly1305();
        $cipher->reset($key, '');

        $sequence = 11;
        $plaintext = \random_bytes(80);
        $packet = $cipher->sealPacket($sequence, 80, $plaintext);

        $iv = static fn (int $counter): string => \pack('P', $counter) . \pack('J', $sequence);

        $polyKey = \substr(
            \openssl_encrypt(\str_repeat("\0", 32), 'chacha20', \substr($key, 0, 32), OPENSSL_RAW_DATA, $iv(0)),
            0,
            32
        );

        $expected = ParagonIE_Sodium_Core_Poly1305::onetimeauth(\substr($packet, 0, -16), $polyKey);

        self::assertSame($expected, \substr($packet, -16));
    }

    public function testShape() {
        $cipher = new ChaCha20Poly1305();

        self::assertSame('chacha20-poly1305@openssh.com', $cipher->getName());
        self::assertSame(64, $cipher->getKeySize());
        self::assertSame(0, $cipher->getIvSize(), 'The sequence number is the nonce, so no IV is derived');
        self::assertSame(8, $cipher->getBlockSize());
        self::assertSame(16, $cipher->getTagLength());
        self::assertSame(4, $cipher->getLengthFieldSize());
        self::assertInstanceOf(AeadCipher::class, $cipher);
    }

    public function testShortKeyIsRejected() {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/64 byte key/');

        (new ChaCha20Poly1305())->reset(\random_bytes(32), '');
    }

    public function testBlockCipherEntryPointsRefuse() {
        $this->expectException(\LogicException::class);

        (new ChaCha20Poly1305())->crypt('data');
    }
}
