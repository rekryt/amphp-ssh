<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use function Amp\delay;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket\InternetAddress;
use Amp\Socket\SocketException;
use Amp\Socket\TlsState;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Message\ChannelData;
use Amp\Ssh\Message\ChannelOpen;
use Amp\Ssh\Message\ChannelOpenConfirmation;
use Amp\Ssh\Message\ChannelOpenFailure;
use Amp\Ssh\SshResource;
use Amp\Ssh\Tests\Channel\FakeHandler;
use function Amp\Ssh\Transport\read_string;
use function Amp\Ssh\Transport\read_uint32;
use Amp\Ssh\Tunnel;
use Amp\Ssh\TunnelAddress;

/**
 * Tunnels without a server.
 *
 * The far end of a tunnel is somewhere the SSH server can reach and the test
 * cannot, so what is worth pinning down here is the request that opens one and
 * the socket behaviour on top of it.
 */
class TunnelTest extends AsyncTestCase {
    private FakeHandler $handler;

    private Dispatcher $dispatcher;

    private SshResource $resource;

    protected function setUp(): void {
        parent::setUp();

        $this->handler = new FakeHandler();
        $this->dispatcher = new Dispatcher($this->handler);
        $this->dispatcher->start();
        $this->resource = new SshResource($this->handler, $this->dispatcher);
    }

    /**
     * The server answers the open with a channel number of its own choosing,
     * deliberately not ours, so that addressing is covered too.
     */
    private function confirmOpen(int $serverChannel = 3): void {
        $confirmation = new ChannelOpenConfirmation();
        $confirmation->recipientChannel = 0;
        $confirmation->senderChannel = $serverChannel;
        $confirmation->initialWindowSize = 0x7FFFFFFF;
        $confirmation->maximumPacketSize = 0x4000;

        $this->handler->deliver($confirmation);
    }

    private function openRequest(): ChannelOpen {
        foreach ($this->handler->written as $message) {
            if ($message instanceof ChannelOpen) {
                return $message;
            }
        }

        self::fail('No channel open was written');
    }

    private function deliverData(string $data, int $recipientChannel = 0): void {
        $message = new ChannelData();
        $message->recipientChannel = $recipientChannel;
        $message->data = $data;

        $this->handler->deliver($message);
    }

    /**
     * RFC 4254 section 7.2: the address to connect to, then where from.
     */
    public function testTheOpenRequestNamesBothEnds() {
        $this->confirmOpen();
        $tunnel = $this->resource->createTunnel('db.internal', 5432, '10.0.0.9', 41234);

        $request = $this->openRequest();
        self::assertSame(ChannelOpen::TYPE_DIRECT_TCPIP, $request->channelType);

        $extra = $request->extraData;
        self::assertSame('db.internal', read_string($extra));
        self::assertSame(5432, read_uint32($extra));
        self::assertSame('10.0.0.9', read_string($extra));
        self::assertSame(41234, read_uint32($extra));
        self::assertSame('', $extra, 'Nothing should follow the originator');

        $tunnel->close();
    }

    public function testDataArrivesAndIsSentOnThePeersChannelNumber() {
        $this->confirmOpen(3);
        $tunnel = $this->resource->createTunnel('db.internal', 5432);

        $this->deliverData("hello from the far end");
        self::assertSame('hello from the far end', $tunnel->read());

        $tunnel->write('and back');

        $sent = \array_values(\array_filter(
            $this->handler->written,
            static fn ($message): bool => $message instanceof ChannelData
        ));

        self::assertCount(1, $sent);
        self::assertSame('and back', $sent[0]->data);
        self::assertSame(3, $sent[0]->recipientChannel);

        $tunnel->close();
    }

    /**
     * A channel delivers whole messages; Socket::read() may want fewer bytes.
     */
    public function testALimitedReadKeepsTheRemainder() {
        $this->confirmOpen();
        $tunnel = $this->resource->createTunnel('db.internal', 5432);

        $this->deliverData('abcdefgh');

        self::assertSame('abc', $tunnel->read(null, 3));
        self::assertSame('de', $tunnel->read(null, 2));
        self::assertTrue($tunnel->isReadable());
        self::assertSame('fgh', $tunnel->read());

        $tunnel->close();
    }

    public function testAnAddressIsAnInternetAddressWhenItCanBe() {
        $this->confirmOpen();
        $tunnel = $this->resource->createTunnel('192.0.2.10', 443, '10.0.0.9', 41234);

        self::assertInstanceOf(InternetAddress::class, $tunnel->getRemoteAddress());
        self::assertSame('192.0.2.10:443', $tunnel->getRemoteAddress()->toString());
        self::assertSame('10.0.0.9:41234', $tunnel->getLocalAddress()->toString());

        $tunnel->close();
    }

    /**
     * The usual case is a name only the server can resolve, which
     * InternetAddress cannot hold.
     */
    public function testAHostnameIsCarriedAsIs() {
        $this->confirmOpen();
        $tunnel = $this->resource->createTunnel('db.internal', 5432);

        $address = $tunnel->getRemoteAddress();

        self::assertInstanceOf(TunnelAddress::class, $address);
        self::assertSame('db.internal:5432', $address->toString());
        self::assertSame('db.internal', $address->getHost());
        self::assertSame(5432, $address->getPort());

        $tunnel->close();
    }

    /**
     * There is no socket resource to enable TLS on, and the interface asks
     * before assuming there is.
     */
    public function testTlsIsDeclinedRatherThanPretended() {
        $this->confirmOpen();
        $tunnel = $this->resource->createTunnel('db.internal', 5432);

        self::assertFalse($tunnel->isTlsConfigurationAvailable());
        self::assertSame(TlsState::Disabled, $tunnel->getTlsState());
        self::assertNull($tunnel->getTlsInfo());

        try {
            $tunnel->setupTls();
            self::fail('Expected setting up TLS to be refused');
        } catch (SocketException $exception) {
            self::assertStringContainsString('no socket resource', $exception->getMessage());
        }

        $tunnel->close();
    }

    /**
     * A refusal on the far side reaches us as the channel not opening.
     */
    public function testAConnectionTheServerCouldNotMakeIsReported() {
        $failure = new ChannelOpenFailure();
        $failure->recipientChannel = 0;
        $failure->reasonCode = 2;
        $failure->description = 'Connection refused';
        $failure->languageTag = 'en';

        $this->handler->deliver($failure);

        $this->expectException(\Amp\Ssh\Channel\ChannelException::class);
        $this->expectExceptionMessage('Connection refused');

        $this->resource->createTunnel('db.internal', 5432);
    }

    public function testClosingATunnelLeavesTheConnectionAlone() {
        $this->confirmOpen();
        $tunnel = $this->resource->createTunnel('db.internal', 5432);

        $closed = false;
        $tunnel->onClose(static function () use (&$closed): void {
            $closed = true;
        });

        $tunnel->close();

        // onClose runs through the event loop rather than inside close(), the
        // same as every other Closable here.
        delay(0);

        self::assertTrue($tunnel->isClosed());
        self::assertTrue($closed);
        self::assertFalse($this->resource->isClosed());
        self::assertFalse($this->handler->closed);
    }
}
