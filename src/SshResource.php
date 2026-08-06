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
