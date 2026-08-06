<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Message;

use Amp\Ssh\Message\ChannelRequest;
use Amp\Ssh\Message\ChannelRequestExitSignal;
use Amp\Ssh\Message\ChannelRequestSignal;
use Amp\Ssh\Message\Message;
use PHPUnit\Framework\TestCase;

/**
 * The two signal messages, which used to be unusable without ext-pcntl.
 *
 * Both built their number-to-name table out of SIG* constants. Outgoing, that
 * made signal() and kill() fatal. Incoming it was worse: decoding a server's
 * exit-signal threw, the read loop treats anything thrown as a dead transport,
 * and a command killed by a signal took the whole connection with it - every
 * other channel on it included.
 */
class SignalRequestTest extends TestCase {
    private static function packString(string $value): string {
        return \pack('Na*', \strlen($value), $value);
    }

    /**
     * The wire form of a channel request, as a server would send it.
     */
    private static function request(string $type, string $extra): string {
        return \pack('CN', Message::SSH_MSG_CHANNEL_REQUEST, 0)
            . self::packString($type)
            . \chr(0)
            . $extra;
    }

    public function testDecodesAnExitSignalWithoutExtPcntl(): void {
        $payload = self::request(
            'exit-signal',
            self::packString('HUP') . \chr(1) . self::packString('Hangup') . self::packString('en')
        );

        $message = ChannelRequest::decode($payload);

        self::assertInstanceOf(ChannelRequestExitSignal::class, $message);
        self::assertSame('HUP', $message->signalName);
        self::assertTrue($message->coreDumped);
        self::assertSame('Hangup', $message->errorMessage);
        self::assertSame('en', $message->languageTag);
    }

    /**
     * A name this platform has no number for must still decode.
     *
     * The connection is worth more than the number: an unknown signal leaves
     * the field null rather than failing the packet.
     */
    public function testDecodesASignalNameItCannotNumber(): void {
        $payload = self::request(
            'exit-signal',
            self::packString('WINCH') . \chr(0) . self::packString('') . self::packString('')
        );

        $message = ChannelRequest::decode($payload);

        self::assertSame('WINCH', $message->signalName);
        self::assertNull($message->signal);
    }

    /**
     * Every field has to survive the round trip.
     *
     * The format string named three of them and pack() dropped the rest, so
     * the error message and the language tag never went out at all.
     */
    public function testExitSignalRoundTripsEveryField(): void {
        $original = new ChannelRequestExitSignal();
        $original->recipientChannel = 0;
        $original->signalName = 'TERM';
        $original->signal = null;
        $original->coreDumped = false;
        $original->errorMessage = 'Terminated';
        $original->languageTag = 'en-GB';

        $decoded = ChannelRequest::decode($original->encode());

        self::assertSame('TERM', $decoded->signalName);
        self::assertFalse($decoded->coreDumped);
        self::assertSame('Terminated', $decoded->errorMessage);
        self::assertSame('en-GB', $decoded->languageTag);
    }

    public function testOutgoingSignalIsNamedNotNumbered(): void {
        $request = new ChannelRequestSignal();
        $request->recipientChannel = 0;
        $request->signal = 9;

        $decoded = ChannelRequest::decode($request->encode());

        self::assertInstanceOf(ChannelRequestSignal::class, $decoded);
        self::assertSame(9, $decoded->signal);
        self::assertStringContainsString('KILL', $request->encode());
    }

    public function testAnUnnameableSignalNumberIsRejectedRatherThanSentEmpty(): void {
        $request = new ChannelRequestSignal();
        $request->recipientChannel = 0;
        $request->signal = 4242;

        $this->expectException(\InvalidArgumentException::class);

        $request->encode();
    }
}
