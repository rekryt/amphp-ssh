<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Channel;

use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Channel\ChannelException;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Channel\Session;
use Amp\Ssh\Message\ChannelClose;
use Amp\Ssh\Message\ChannelData;
use Amp\Ssh\Message\ChannelOpenConfirmation;

/**
 * The channel lifecycle, without a server.
 *
 * These pin down the single most important behaviour of this layer: losing the
 * connection and closing it cleanly are NOT the same thing. A dropped
 * connection has to surface as a thrown ChannelException, an orderly close as a
 * plain end of stream. Everything above - Process::join() throwing versus
 * resolving - is built on that distinction.
 */
class DispatcherLifecycleTest extends AsyncTestCase {
    private function openSession(FakeHandler $handler, Dispatcher $dispatcher, int $channelId = 0): Session {
        $confirmation = new ChannelOpenConfirmation();
        $confirmation->recipientChannel = $channelId;
        $confirmation->senderChannel = $channelId;
        $confirmation->initialWindowSize = 0x7FFFFFFF;
        $confirmation->maximumPacketSize = 0x4000;

        $session = $dispatcher->createSession();
        $handler->deliver($confirmation);
        $session->open();

        return $session;
    }

    public function testLostConnectionErrorsPendingRequests() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $session = $this->openSession($handler, $dispatcher);

        $handler->disconnect();

        $this->expectException(ChannelException::class);

        $session->getRequestIterator()->continue();
    }

    public function testLostConnectionStillEndsDataStreamCleanly() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $session = $this->openSession($handler, $dispatcher);

        $handler->disconnect();

        // Data already received stays readable and the stream simply ends;
        // only request results are an error, because an answer that will never
        // arrive has to be reported.
        self::assertFalse($session->getDataIterator()->continue());
        self::assertFalse($session->getDataExtendedIterator()->continue());
    }

    public function testOrderlyCloseCompletesInsteadOfFailing() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $session = $this->openSession($handler, $dispatcher);

        $dispatcher->close();

        self::assertFalse($session->getRequestIterator()->continue());
    }

    public function testTransportFailureIsReportedAsChannelExceptionAndClosesConnection() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $session = $this->openSession($handler, $dispatcher);

        // A bad MAC used to escape the read loop and take down the event loop
        // while the channels waited forever.
        $handler->failWith(new \RuntimeException('Invalid mac'));

        try {
            $session->getRequestIterator()->continue();
            self::fail('Expected a ChannelException');
        } catch (ChannelException $exception) {
            self::assertStringContainsString('Invalid mac', $exception->getMessage());
        }

        self::assertTrue($handler->closed, 'The transport must be closed when the read loop fails');
    }

    /**
     * Closing from both sides at once must not blow up.
     *
     * A Queue throws an Error when completed twice, and an Error is not an
     * Exception - the v2 catch would not have caught it.
     */
    public function testCloseIsIdempotentWhenServerAlsoCloses() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $session = $this->openSession($handler, $dispatcher);

        $close = new ChannelClose();
        $close->recipientChannel = 0;

        $session->close();
        $handler->deliver($close);

        self::assertFalse($session->getRequestIterator()->continue());
    }

    /**
     * One channel nobody reads must not stall the others.
     *
     * In v2 the dispatcher awaited every emit, so an unread stdout blocked the
     * single read loop and with it every other channel on the connection.
     */
    public function testSlowConsumerDoesNotStallAnotherChannel() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $ignored = $this->openSession($handler, $dispatcher, 0);
        $active = $this->openSession($handler, $dispatcher, 1);

        // Nobody ever reads channel 0.
        for ($i = 0; $i < 64; ++$i) {
            $data = new ChannelData();
            $data->recipientChannel = 0;
            $data->data = 'flood';
            $handler->deliver($data);
        }

        $expected = new ChannelData();
        $expected->recipientChannel = 1;
        $expected->data = 'still moving';
        $handler->deliver($expected);

        self::assertTrue($active->getDataIterator()->continue());
        self::assertSame('still moving', $active->getDataIterator()->getValue()->data);
    }
}
