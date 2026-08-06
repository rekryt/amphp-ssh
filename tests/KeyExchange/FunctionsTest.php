<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\KeyExchange;

use function Amp\Ssh\KeyExchange\twos_compliment;
use PHPUnit\Framework\TestCase;

class FunctionsTest extends TestCase {
    public function testKeepsAPlainValueUnchanged(): void {
        self::assertSame("\x01\x02\x03", twos_compliment("\x01\x02\x03"));
    }

    public function testPrependsAZeroWhenTheTopBitIsSet(): void {
        // Otherwise the value reads as negative.
        self::assertSame("\x00\x80", twos_compliment("\x80"));
        self::assertSame("\x00\xFF\xFF", twos_compliment("\xFF\xFF"));
    }

    /**
     * RFC 4251: "Unnecessary leading bytes with the value 0 [...] MUST NOT be
     * included.".
     *
     * A curve25519 shared secret is 32 random bytes, so it starts with a zero
     * about once in every 256 exchanges. Sending that zero produced a
     * different exchange hash from the server's, and the host key signature
     * was rejected on a connection that was in no way different from the ones
     * before it.
     */
    public function testStripsLeadingZeroBytes(): void {
        self::assertSame("\x01\x02", twos_compliment("\x00\x01\x02"));
        self::assertSame("\x01\x02", twos_compliment("\x00\x00\x00\x01\x02"));
    }

    public function testStripsThenAddsBackTheSignByte(): void {
        // The zero in front of a high bit is required, so it survives.
        self::assertSame("\x00\x80\x01", twos_compliment("\x00\x80\x01"));
        self::assertSame("\x00\x80\x01", twos_compliment("\x00\x00\x80\x01"));
    }

    public function testEncodesZeroAsNothing(): void {
        self::assertSame('', twos_compliment("\x00"));
        self::assertSame('', twos_compliment("\x00\x00\x00\x00"));
    }

    /**
     * Cross-checks the encoding against the arbitrary precision maths PHP has
     * built in, which is where the definition of "the shortest signed big
     * endian form" can be taken from independently.
     */
    public function testAgreesWithGmpOrBcmathOverManyRandomValues(): void {
        if (!\function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is not loaded');
        }

        for ($i = 0; $i < 2000; ++$i) {
            $value = \random_bytes(32);
            $expected = gmp_export(gmp_import($value), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

            if ($expected !== '' && (\ord($expected[0]) & 0x80) !== 0) {
                $expected = "\x00" . $expected;
            }

            self::assertSame(
                \bin2hex($expected),
                \bin2hex(twos_compliment($value)),
                'mismatch for ' . \bin2hex($value)
            );
        }
    }
}
