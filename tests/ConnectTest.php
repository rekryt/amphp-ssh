<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use function Amp\async;
use Amp\Cancellation;
use Amp\CancelledException;
use Amp\DeferredFuture;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket;
use Amp\Ssh\Authentication\UsernamePassword;
use function Amp\Ssh\connect;
use Amp\Ssh\Transport\ServerIdentificationException;
use Amp\TimeoutCancellation;

/**
 * connect() against a scripted TCP peer.
 *
 * No sshd needed: these cover the parts of connection setup that are about
 * framing and failure handling rather than the SSH protocol proper - above all
 * the rule that nothing half-negotiated ever escapes connect().
 */
class ConnectTest extends AsyncTestCase {
    private ?Socket\ServerSocket $server = null;

    private ?DeferredFuture $peerEof = null;

    protected function tearDown(): void {
        $this->server?->close();

        parent::tearDown();
    }

    /**
     * Starts a fake peer and returns the address to connect to.
     *
     * @param callable(Socket\Socket): void $script What the peer does once a
     *                                              client has connected.
     */
    private function serve(callable $script): string {
        $this->server = Socket\listen('127.0.0.1:0');
        $this->peerEof = new DeferredFuture();

        $server = $this->server;
        $peerEof = $this->peerEof;

        async(static function () use ($server, $script, $peerEof): void {
            try {
                $client = $server->accept();

                if ($client === null) {
                    return;
                }

                $script($client);

                // Returns null as soon as the client hangs up.
                while ($client->read() !== null) {
                }

                $client->close();
            } catch (\Throwable) {
                // Assertions belong to the client side.
            } finally {
                if (!$peerEof->isComplete()) {
                    $peerEof->complete();
                }
            }
        });

        return $server->getAddress()->toString();
    }

    /**
     * The peer must observe the connection being closed from our side.
     */
    private function assertPeerSawEof(): void {
        try {
            $this->peerEof->getFuture()->await(new TimeoutCancellation(2));
        } catch (CancelledException) {
            self::fail('connect() left the socket open instead of closing it');
        }

        self::assertTrue(true, 'The peer observed the socket being closed');
    }

    private function dial(string $address, float $timeout): void {
        connect(
            $address,
            new UsernamePassword('root', 'root'),
            null,
            'SSH-2.0-AmpSSH_0.1',
            new TimeoutCancellation($timeout)
        );
    }

    /**
     * A preamble line and the identification arriving in one segment must both
     * be handled without waiting for further data.
     */
    public function testIdentificationSharingASegmentWithAPreamble() {
        $address = $this->serve(static function (Socket\Socket $client): void {
            $client->read();
            $client->write("Welcome to the fake server\r\nSSH-2.0-FakeServer_1.0\r\n");
            // Never a valid packet, so the handshake stalls until cancelled.
            $client->write(\pack('N', 0x00FFFFFF) . 'not really a packet');
        });

        try {
            $this->dial($address, 0.5);
            self::fail('Expected the handshake to be cancelled');
        } catch (CancelledException) {
            // Reaching the key exchange at all proves the identification was
            // parsed out of that first combined segment.
        }

        $this->assertPeerSawEof();
    }

    /**
     * Cancelling mid-handshake leaves nothing half-negotiated behind.
     */
    public function testCancellationDuringHandshakeClosesTheSocket() {
        $address = $this->serve(static function (Socket\Socket $client): void {
            $client->read();
            $client->write("SSH-2.0-FakeServer_1.0\r\n");
            // Say nothing further; the client waits for KEXINIT.
        });

        try {
            $this->dial($address, 0.3);
            self::fail('Expected the handshake to be cancelled');
        } catch (CancelledException) {
            // expected
        }

        $this->assertPeerSawEof();
    }

    /**
     * A peer that hangs up before sending its identification is reported
     * rather than waited on forever.
     *
     * Reported as its own failure, too: nothing was authenticated here, and
     * calling it an authentication failure - as this did until 2.0 - sends
     * whoever reads the log off to check credentials that were never offered.
     */
    public function testConnectionClosedBeforeIdentification() {
        $address = $this->serve(static function (Socket\Socket $client): void {
            $client->close();
        });

        $this->expectException(ServerIdentificationException::class);

        $this->dial($address, 2);
    }

    /**
     * A peer that talks without ever starting a line is given up on.
     *
     * Complete preamble lines are consumed as they arrive, so only unterminated
     * data accumulates - which a peer can produce indefinitely at no cost to
     * itself. The bound is what keeps that from being an easy way to exhaust
     * the client's memory.
     */
    public function testPeerThatSendsEndlessDataWithoutALine() {
        $address = $this->serve(static function (Socket\Socket $client): void {
            $client->read();

            $chunk = \str_repeat('x', 8192);

            for ($written = 0; $written <= ServerIdentificationException::MAX_PREAMBLE_BYTES; $written += 8192) {
                $client->write($chunk);
            }
        });

        $this->expectException(ServerIdentificationException::class);

        $this->dial($address, 5);
    }

    /**
     * A connector handed to connect() is the one that makes the TCP
     * connection. That is what lets a caller route the connection through a
     * proxy or another tunnel without swapping the process-wide connector.
     */
    public function testGivenConnectorMakesTheConnection() {
        $address = $this->serve(static function (Socket\Socket $client): void {
            $client->read();
            $client->write("SSH-2.0-FakeServer_1.0\r\n");
            // Say nothing further; the client waits for KEXINIT.
        });

        // Redirects every connection to the fake peer, so reaching that peer
        // while dialing an unresolvable name proves this connector was used.
        $connector = new class($address) implements Socket\SocketConnector {
            public ?string $requestedUri = null;

            public function __construct(private readonly string $address) {
            }

            public function connect(
                Socket\SocketAddress|string $uri,
                ?Socket\ConnectContext $context = null,
                ?Cancellation $cancellation = null
            ): Socket\Socket {
                $this->requestedUri = (string) $uri;

                return (new Socket\DnsSocketConnector())->connect($this->address, $context, $cancellation);
            }
        };

        try {
            connect(
                'ssh.example.invalid:22',
                new UsernamePassword('root', 'root'),
                null,
                'SSH-2.0-AmpSSH_0.1',
                new TimeoutCancellation(0.3),
                null,
                null,
                $connector
            );
            self::fail('Expected the handshake to be cancelled');
        } catch (CancelledException) {
            // The fake peer never answers the key exchange; getting as far as
            // waiting on it proves the connection went through the connector.
        }

        self::assertSame('ssh.example.invalid:22', $connector->requestedUri);
        $this->assertPeerSawEof();
    }

    /**
     * Garbage where the identification belongs must not be mistaken for it.
     */
    public function testPeerThatNeverSendsAnIdentification() {
        $address = $this->serve(static function (Socket\Socket $client): void {
            $client->read();
            $client->write("HTTP/1.1 400 Bad Request\r\nnot ssh at all\r\n");
        });

        $this->expectException(CancelledException::class);

        $this->dial($address, 0.3);
    }
}
