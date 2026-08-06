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
     * Asserts the two RFC 4251 rules over random input, with no oracle.
     *
     * An mpint is defined by exactly those two properties, so they can be
     * checked directly - and that is worth more here than comparing against a
     * big-integer library would be. Naming one would tie this file's coding
     * style to the machine it is linted on: php-cs-fixer decides whether a
     * function is "internal" by asking the running PHP, so gmp_import needs a
     * leading backslash where ext-gmp is loaded and must not have one where it
     * is missing.
     */
    public function testRandomValuesKeepTheirValueAndCarryNoSpareZero(): void {
        for ($i = 0; $i < 2000; ++$i) {
            $value = \random_bytes(32);
            $encoded = twos_compliment($value);
            $where = ' for ' . \bin2hex($value);

            // The number itself is unchanged: the same bytes once leading
            // zeros are set aside on both sides.
            self::assertSame(
                \bin2hex(\ltrim($value, "\x00")),
                \bin2hex(\ltrim($encoded, "\x00")),
                'the value changed' . $where
            );

            if ($encoded === '') {
                continue;
            }

            // Never reads as negative.
            self::assertSame(0, \ord($encoded[0]) & 0x80, 'high bit left exposed' . $where);

            // And the zero in front, when there is one, is there because the
            // byte after it needs it.
            if ($encoded[0] === "\x00") {
                self::assertNotSame(0, \ord($encoded[1]) & 0x80, 'unnecessary leading zero' . $where);
            }
        }
    }
}
