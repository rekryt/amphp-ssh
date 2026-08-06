<?php declare(strict_types=1);

namespace Amp\Ssh\Channel;

use function Amp\async;
use Amp\Future;
use Amp\Pipeline\Queue;
use Amp\Ssh\Message\ChannelClose;
use Amp\Ssh\Message\ChannelOpen;
use Amp\Ssh\Message\KeyExchangeInit;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Negotiator;
use Amp\Ssh\Transport\BinaryPacketHandler;
use Amp\Ssh\Transport\MessageHandler;
use Amp\Ssh\Transport\RekeyPacketHandler;

/**
 * Demultiplexes incoming channel messages onto per-channel queues.
 *
 * @internal
 */
class Dispatcher {
    /** @var Queue[] */
    private array $channelQueues = [];

    private BinaryPacketHandler $handler;

    private int $channelSequence = 0;

    private bool $running = true;

    private bool $closed = false;

    private ?Future $loop = null;

    private ?Negotiator $negotiator = null;

    private ?MessageHandler $gate = null;

    private string $serverIdentification = '';

    private string $clientIdentification = '';

    public function __construct(BinaryPacketHandler $handler) {
        $this->handler = $handler;
    }

    public function start(): void {
        if ($this->closed) {
            throw new \RuntimeException('SSH Connection is closed');
        }

        $this->loop = async(function (): void {
            try {
                while ($this->running) {
                    $message = $this->handler->read();

                    if ($message === null) {
                        $this->doFail(new ChannelException('SSH connection was closed by remote server'));

                        return;
                    }

                    if (!$message instanceof Message) {
                        continue;
                    }

                    $this->route($message);
                }
            } catch (\Throwable $exception) {
                // Anything thrown by the transport - a bad MAC, an undecodable
                // packet, a dead socket - kills this connection, not the event
                // loop. Without this the exception escaped the fiber and took
                // the whole process down while the channels waited forever.
                $this->doFail(new ChannelException('SSH connection failed: ' . $exception->getMessage(), 0, $exception));
                $this->handler->close();
            }
        });
    }

    /**
     * Wires up support for server initiated key re-exchange.
     *
     * Without this a mid-session KEXINIT is silently dropped: the server waits
     * for a reply that never comes and eventually drops the connection, which
     * looks from here like an unexplained disconnect under load.
     */
    public function enableRekey(
        Negotiator $negotiator,
        MessageHandler $gate,
        string $serverIdentification,
        string $clientIdentification
    ): void {
        $this->negotiator = $negotiator;
        $this->gate = $gate;
        $this->serverIdentification = $serverIdentification;
        $this->clientIdentification = $clientIdentification;
    }

    private function route(Message $message): void {
        $type = $message::getNumber();

        if ($message instanceof KeyExchangeInit) {
            $this->rekey($message);

            return;
        }

        if ($type < Message::SSH_MSG_CHANNEL_OPEN || $type > Message::SSH_MSG_CHANNEL_FAILURE) {
            return;
        }

        $channelId = $message instanceof ChannelOpen ? $message->senderChannel : $message->recipientChannel;

        if (!\array_key_exists($channelId, $this->channelQueues)) {
            return;
        }

        $queue = $this->channelQueues[$channelId];

        // Deliberately do NOT await the push: this loop is the only reader of
        // the connection, so blocking it on one slow channel stalls every other
        // channel and, past the TCP window, the connection itself. A consumer
        // that has gone away disposes its queue, which makes the push fail with
        // DisposedException - expected, and equally not worth blocking on.
        //
        // The cost is an unbounded buffer per channel. Bounding it belongs with
        // SSH window accounting, which is not implemented yet.
        $queue->pushAsync($message)->ignore();

        if ($message instanceof ChannelClose) {
            $queue->complete();

            unset($this->channelQueues[$channelId]);
        }
    }

    /**
     * Answers a server's KEXINIT and installs the new keys.
     *
     * Runs inside the read loop, which is what makes it safe: this fiber owns
     * reading, so the exchange cannot race with the ordinary dispatch. Writes
     * from other fibers are held back by the gate, and packets that arrive
     * mid-exchange - legal until NEWKEYS - are handed back to route().
     */
    private function rekey(KeyExchangeInit $serverKex): void {
        if ($this->negotiator === null || $this->gate === null) {
            throw new ChannelException(
                'The server asked for a key re-exchange, which this connection was not set up to perform.'
            );
        }

        $this->gate->beginRekey();

        try {
            $this->negotiator->rekey(
                new RekeyPacketHandler($this->handler, function (Message $message): void {
                    $this->route($message);
                }),
                $serverKex,
                $this->serverIdentification,
                $this->clientIdentification
            );
        } finally {
            $this->gate->endRekey();
        }
    }

    /**
     * The connection died under us: every channel learns about it as an error.
     *
     * This is the half of the lifecycle that must stay distinct from close():
     * consumers see a thrown ChannelException, not a clean end of stream.
     */
    private function doFail(\Throwable $reason): void {
        $this->stop();

        foreach ($this->channelQueues as $channelId => $queue) {
            unset($this->channelQueues[$channelId]);

            $queue->error($reason);
        }
    }

    public function stop(): void {
        $this->running = false;
    }

    /**
     * Orderly shutdown: every channel ends normally.
     *
     * The mirror image of doFail(); consumers see the queue complete, so a
     * pending join() resolves instead of throwing.
     */
    public function close(): void {
        $this->closed = true;

        $this->stop();

        foreach ($this->channelQueues as $channelId => $queue) {
            unset($this->channelQueues[$channelId]);

            $queue->complete();
        }
    }

    public function createSession(): Session {
        $queue = new Queue();

        // iterate() is called exactly once and the iterator is owned by the
        // Session for its whole life. Creating a second iterator and letting it
        // go out of scope would dispose the queue for everyone.
        $session = new Session($this->handler, $queue->iterate(), $this->channelSequence);

        $this->channelQueues[$this->channelSequence] = $queue;
        ++$this->channelSequence;

        return $session;
    }

    /**
     * A channel the server opens towards an address of our choosing.
     *
     * @see createSession() for why iterate() is called exactly once.
     */
    public function createDirectTcpIp(
        string $host,
        int $port,
        string $originatorHost,
        int $originatorPort
    ): DirectTcpIp {
        $queue = new Queue();

        $channel = new DirectTcpIp(
            $this->handler,
            $queue->iterate(),
            $this->channelSequence,
            $host,
            $port,
            $originatorHost,
            $originatorPort
        );

        $this->channelQueues[$this->channelSequence] = $queue;
        ++$this->channelSequence;

        return $channel;
    }
}
