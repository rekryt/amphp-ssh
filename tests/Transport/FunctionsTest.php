<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Transport;

use function Amp\Ssh\Transport\read_boolean;
use function Amp\Ssh\Transport\read_byte;
use function Amp\Ssh\Transport\read_bytes;
use function Amp\Ssh\Transport\read_mpint;
use function Amp\Ssh\Transport\read_namelist;
use function Amp\Ssh\Transport\read_string;
use function Amp\Ssh\Transport\read_uint32;
use function Amp\Ssh\Transport\read_uint64;
use Amp\Ssh\Transport\TruncatedPacketException;
use PHPUnit\Framework\TestCase;

/**
 * The wire readers are the first thing a malformed or truncated packet hits.
 *
 * Under strict_types an out-of-bounds unpack() returns false, which used to
 * surface as a TypeError from inside the parser. Every reader must instead
 * reject short input with a protocol level exception.
 */
class FunctionsTest extends TestCase {
    public function testReadByte() {
        $payload = \pack('C', 0x42) . 'rest';

        self::assertSame(0x42, read_byte($payload));
        self::assertSame('rest', $payload);
    }

    public function testReadByteOnEmptyPayload() {
        $payload = '';

        self::expectException(TruncatedPacketException::class);

        read_byte($payload);
    }

    public function testReadBoolean() {
        $payload = \pack('CC', 1, 0);

        self::assertTrue(read_boolean($payload));
        self::assertFalse(read_boolean($payload));
    }

    public function testReadBooleanOnEmptyPayload() {
        $payload = '';

        self::expectException(TruncatedPacketException::class);

        read_boolean($payload);
    }

    public function testReadUint32() {
        $payload = \pack('N', 0x29B7F4AA) . 'rest';

        self::assertSame(0x29B7F4AA, read_uint32($payload));
        self::assertSame('rest', $payload);
    }

    /**
     * @dataProvider provideShortUint32
     */
    public function testReadUint32OnShortPayload(string $payload) {
        self::expectException(TruncatedPacketException::class);

        read_uint32($payload);
    }

    public function provideShortUint32(): iterable {
        yield 'empty' => [''];
        yield 'one byte' => ["\x00"];
        yield 'two bytes' => ["\x00\x00"];
        yield 'three bytes' => ["\x00\x00\x00"];
    }

    public function testReadUint64() {
        $payload = \pack('J', 0x0102030405060708) . 'rest';

        self::assertSame(0x0102030405060708, read_uint64($payload));
        self::assertSame('rest', $payload);
    }

    public function testReadUint64OnShortPayload() {
        $payload = \pack('N', 1);

        self::expectException(TruncatedPacketException::class);

        read_uint64($payload);
    }

    public function testReadBytes() {
        $payload = 'abcdef';

        self::assertSame('abc', read_bytes($payload, 3));
        self::assertSame('def', $payload);
    }

    public function testReadBytesBeyondPayload() {
        $payload = 'abc';

        self::expectException(TruncatedPacketException::class);

        read_bytes($payload, 4);
    }

    public function testReadString() {
        $payload = \pack('Na*', 7, 'testing') . 'rest';

        self::assertSame('testing', read_string($payload));
        self::assertSame('rest', $payload);
    }

    public function testReadEmptyString() {
        $payload = \pack('N', 0);

        self::assertSame('', read_string($payload));
        self::assertSame('', $payload);
    }

    /**
     * A length prefix larger than what is left in the packet is the classic
     * truncation signature; it must not yield a silently shortened string.
     */
    public function testReadStringWithLengthBeyondPayload() {
        $payload = \pack('Na*', 32, 'testing');

        self::expectException(TruncatedPacketException::class);

        read_string($payload);
    }

    public function testReadStringWithTruncatedLengthPrefix() {
        $payload = "\x00\x00";

        self::expectException(TruncatedPacketException::class);

        read_string($payload);
    }

    public function testReadMpintWithLengthBeyondPayload() {
        $payload = \pack('Na*', 16, "\x01\x02");

        self::expectException(TruncatedPacketException::class);

        read_mpint($payload);
    }

    public function testReadNamelist() {
        $names = 'zlib,none';
        $payload = \pack('Na*', \strlen($names), $names);

        self::assertSame(['zlib', 'none'], read_namelist($payload));
    }

    public function testReadEmptyNamelist() {
        $payload = \pack('N', 0);

        self::assertSame([], read_namelist($payload));
    }

    public function testReadNamelistWithLengthBeyondPayload() {
        $payload = \pack('Na*', 64, 'zlib,none');

        self::expectException(TruncatedPacketException::class);

        read_namelist($payload);
    }
}
