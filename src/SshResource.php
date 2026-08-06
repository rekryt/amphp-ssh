<?php declare(strict_types=1);

namespace Amp\Ssh;

use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Channel\Session;
use Amp\Ssh\Message\Disconnect;
use Amp\Ssh\Transport\BinaryPacketHandler;

/**
 * @internal
 */
class SshResource {
    private BinaryPacketHandler $handler;

    private Dispatcher $dispatcher;

    private bool $running = true;

    public function __construct(BinaryPacketHandler $handler, Dispatcher $dispatcher) {
        $this->handler = $handler;
        $this->dispatcher = $dispatcher;
    }

    public function createSession(): Session {
        return $this->dispatcher->createSession();
    }

    /**
     * Has the server connect to an address, and hands back the other end.
     *
     * The returned Tunnel is an Amp\Socket\Socket, so anything that takes one
     * can be pointed through it. The address is resolved by the server, which
     * is the point: it reaches what the server can reach.
     *
     * The originator is what the server records and matches its own "from"
     * rules against. It is advisory - nothing verifies it - so the loopback
     * default is a reasonable statement that the connection began here.
     *
     * @throws Channel\ChannelException If the server refuses to open it, which
     *                                  is what a refused connection on the far
     *                                  side looks like from here.
     */
    public function createTunnel(
        string $host,
        int $port,
        string $originatorHost = '127.0.0.1',
        int $originatorPort = 0
    ): Tunnel {
        $channel = $this->dispatcher->createDirectTcpIp($host, $port, $originatorHost, $originatorPort);
        $channel->open();

        return new Tunnel($channel);
    }

    /**
     * Orderly shutdown.
     *
     * Channels are completed first, so consumers see a clean end of stream
     * rather than an error - the distinction the whole channel lifecycle rests
     * on. Only then is SSH_MSG_DISCONNECT sent and the socket closed.
     */
    public function close(): void {
        if (!$this->running) {
            return;
        }

        $this->running = false;
        $this->dispatcher->close();

        try {
            $this->handler->write(new Disconnect());
        } catch (\Throwable) {
            // The peer may already be gone; closing is still the right move.
        }

        $this->handler->close();
    }

    public function isClosed(): bool {
        return !$this->running;
    }

    public function __destruct() {
        $this->close();
    }
}
