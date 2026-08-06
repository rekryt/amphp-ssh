<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Channel;

use function Amp\async;
use function Amp\delay;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Channel\Session;
use Amp\Ssh\Message\ChannelData;
use Amp\Ssh\Message\ChannelOpenConfirmation;
use Amp\Ssh\Message\ChannelWindowAdjust;
use Amp\TimeoutCancellation;

/**
 * Channel flow control (RFC 4254 section 5.2).
 *
 * None of this existed: outgoing data was written as one message regardless of
 * the peer's maximum packet size, the window it granted was never tracked, and
 * SSH_MSG_CHANNEL_WINDOW_ADJUST was routed to the channel and then dropped.
 */
class FlowControlTest extends AsyncTestCase {
    private FakeHandler $handler;

    private Dispatcher $dispatcher;

    protected function setUp(): void {
        parent::setUp();

        $this->handler = new FakeHandler();
        $this->dispatcher = new Dispatcher($this->handler);
        $this->dispatcher->start();
    }

    private function openSession(int $window, int $maxPacket, int $channelId = 0): Session {
        $confirmation = new ChannelOpenConfirmation();
        $confirmation->recipientChannel = $channelId;
        $confirmation->senderChannel = $channelId;
        $confirmation->initialWindowSize = $window;
        $confirmation->maximumPacketSize = $maxPacket;

        $session = $this->dispatcher->createSession();
        $this->handler->deliver($confirmation);
        $session->open();

        return $session;
    }

    /** @return ChannelData[] */
    private function sentData(): array {
        return \array_values(\array_filter(
            $this->handler->written,
            static fn ($message) => $message instanceof ChannelData
        ));
    }

    public function testWriteIsSplitAcrossTheMaximumPacketSize() {
        $session = $this->openSession(1024 * 1024, 4096);

        $session->data(\str_repeat('a', 10000));

        $chunks = $this->sentData();

        self::assertGreaterThan(1, \count($chunks), 'A large write must be split');

        foreach ($chunks as $chunk) {
            self::assertLessThanOrEqual(4096, \strlen($chunk->data));
        }

        self::assertSame(10000, \array_sum(\array_map(static fn ($c) => \strlen($c->data), $chunks)));
        self::assertSame(\str_repeat('a', 10000), \implode('', \array_map(static fn ($c) => $c->data, $chunks)));
    }

    public function testWriteStopsWhenTheWindowIsExhausted() {
        $session = $this->openSession(100, 4096);

        $writer = async(static fn () => $session->data(\str_repeat('b', 250)));

        // async() only schedules the fiber; let it run up to the point where it
        // blocks on the window before inspecting what was sent.
        delay(0.01);

        // Only the granted 100 bytes may go out; the rest waits.
        self::assertSame(100, \array_sum(\array_map(static fn ($c) => \strlen($c->data), $this->sentData())));
        self::assertFalse($writer->isComplete(), 'The write must still be waiting for window space');

        $adjust = new ChannelWindowAdjust();
        $adjust->recipientChannel = 0;
        $adjust->bytesToAdd = 1000;
        $this->handler->deliver($adjust);

        $writer->await(new TimeoutCancellation(2));

        self::assertSame(250, \array_sum(\array_map(static fn ($c) => \strlen($c->data), $this->sentData())));
    }

    /**
     * A closed channel must release a writer parked on the window rather than
     * leave it suspended for good.
     */
    public function testCloseReleasesAWriterWaitingForWindow() {
        $session = $this->openSession(10, 4096);

        $writer = async(static fn () => $session->data(\str_repeat('c', 100)));

        delay(0.01);

        self::assertFalse($writer->isComplete());

        $this->handler->disconnect();

        $this->expectException(\Amp\Ssh\Channel\ChannelException::class);

        $writer->await(new TimeoutCancellation(2));
    }

    /**
     * Receiving data has to be acknowledged, otherwise a peer that respects the
     * window we advertised stops sending halfway through a large transfer.
     */
    public function testReceivingDataEventuallyExtendsOurWindow() {
        $session = $this->openSession(1024 * 1024, 32768);

        $chunk = \str_repeat('d', 64 * 1024);
        $iterator = $session->getDataIterator();

        // Push past the halfway mark of the advertised 2 MiB receive window.
        for ($i = 0; $i < 20; ++$i) {
            $data = new ChannelData();
            $data->recipientChannel = 0;
            $data->data = $chunk;
            $this->handler->deliver($data);

            $iterator->continue();
        }

        $adjustments = \array_filter(
            $this->handler->written,
            static fn ($message) => $message instanceof ChannelWindowAdjust
        );

        self::assertNotEmpty($adjustments, 'The client must top its receive window back up');

        foreach ($adjustments as $adjustment) {
            self::assertGreaterThan(0, $adjustment->bytesToAdd);
        }
    }

    public function testEmptyWriteSendsNothing() {
        $session = $this->openSession(1024, 4096);

        $session->data('');

        self::assertSame([], $this->sentData());
    }
}
