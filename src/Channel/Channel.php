<?php declare(strict_types=1);

namespace Amp\Ssh\Channel;

use function Amp\async;
use Amp\DeferredFuture;
use Amp\Future;
use Amp\Pipeline\ConcurrentIterator;
use Amp\Pipeline\Queue;
use Amp\Ssh\Message\ChannelClose;
use Amp\Ssh\Message\ChannelData;
use Amp\Ssh\Message\ChannelEof;
use Amp\Ssh\Message\ChannelExtendedData;
use Amp\Ssh\Message\ChannelFailure;
use Amp\Ssh\Message\ChannelOpen;
use Amp\Ssh\Message\ChannelOpenConfirmation;
use Amp\Ssh\Message\ChannelOpenFailure;
use Amp\Ssh\Message\ChannelRequest;
use Amp\Ssh\Message\ChannelSuccess;
use Amp\Ssh\Message\ChannelWindowAdjust;
use Amp\Ssh\Transport\BinaryPacketWriter;
use Revolt\EventLoop;

/**
 * @internal
 */
abstract class Channel {
    private const STATE_PENDING = 0;

    private const STATE_OPEN = 1;

    private const STATE_FINISHED = 2;

    /**
     * How much the peer may send us before it has to wait for an adjustment.
     *
     * The old code advertised 0x7FFFFFFF and never replenished, which is legal
     * but turns the receive window into no limit at all - and with it the
     * per-channel queue, which buffers whatever arrives. A finite window is
     * what actually bounds that buffer.
     */
    private const LOCAL_WINDOW_SIZE = 2 * 1024 * 1024;

    /** Largest SSH packet we accept; OpenSSH uses the same value. */
    private const LOCAL_MAX_PACKET_SIZE = 32768;

    /**
     * Room left for the packet and CHANNEL_DATA headers inside the peer's
     * maximum packet size, which covers the whole packet rather than just the
     * payload.
     */
    private const PACKET_HEADER_ALLOWANCE = 64;

    /** Our number for this channel; what the peer addresses us by. */
    protected int $channelId;

    /**
     * The peer's number for the same channel, which every message we send has
     * to carry.
     *
     * The two are not the same thing and only look like it: each side numbers
     * its own end, and the peer's number arrives in the open confirmation. This
     * used to send our own number back, which works exactly as long as both
     * sides happen to allocate alike - true for the first channel on a
     * connection, and not true once one has been closed and another opened,
     * because a server is free to reuse the number it just freed while we have
     * moved on to the next.
     */
    protected int $peerChannelId;

    protected BinaryPacketWriter $writer;

    protected ConcurrentIterator $channelMessage;

    protected Queue $dataQueue;

    protected Queue $dataExtendedQueue;

    protected Queue $requestQueue;

    protected Queue $requestResultQueue;

    /**
     * Each queue is iterated exactly once, here, and its iterator lives as long
     * as the channel does.
     *
     * Queue::iterate() hands out a NEW iterator on every call, and an iterator
     * being garbage collected disposes the underlying queue. Calling iterate()
     * ad hoc - as the v2 code did for request results - therefore destroys the
     * queue for everyone the moment the temporary iterator is collected.
     */
    protected ConcurrentIterator $dataIterator;

    protected ConcurrentIterator $dataExtendedIterator;

    protected ConcurrentIterator $requestIterator;

    protected ConcurrentIterator $requestResultIterator;

    private int $state = self::STATE_PENDING;

    private ?Future $dispatcher = null;

    /** Bytes we may still send before the peer extends its window. */
    private int $remoteWindow = 0;

    /** Largest packet the peer is willing to receive. */
    private int $remoteMaxPacket = self::LOCAL_MAX_PACKET_SIZE;

    /** Bytes the peer may still send us before we extend ours. */
    private int $localWindow = self::LOCAL_WINDOW_SIZE;

    /** Resolved whenever the peer extends its window. */
    private ?DeferredFuture $windowWaiter = null;

    /** Whether CHANNEL_CLOSE has gone out; it may only be sent once. */
    private bool $closeSent = false;

    public function __construct(BinaryPacketWriter $writer, ConcurrentIterator $channelMessage, int $channelId) {
        $this->channelId = $channelId;

        // Until the confirmation arrives there is nothing better to assume, and
        // nothing is sent on the channel before it does.
        $this->peerChannelId = $channelId;
        $this->writer = $writer;
        $this->channelMessage = $channelMessage;

        $this->dataQueue = new Queue();
        $this->dataExtendedQueue = new Queue();
        $this->requestQueue = new Queue();
        $this->requestResultQueue = new Queue();

        $this->dataIterator = $this->dataQueue->iterate();
        $this->dataExtendedIterator = $this->dataExtendedQueue->iterate();
        $this->requestIterator = $this->requestQueue->iterate();
        $this->requestResultIterator = $this->requestResultQueue->iterate();
    }

    public function getChannelId(): int {
        return $this->channelId;
    }

    /**
     * What this channel type appends to the open request, already encoded.
     *
     * A session appends nothing, which is why this defaults to empty; a
     * forwarding channel names the address it wants reached.
     */
    protected function getOpenExtraData(): string {
        return '';
    }

    public function getDataIterator(): ConcurrentIterator {
        return $this->dataIterator;
    }

    public function getDataExtendedIterator(): ConcurrentIterator {
        return $this->dataExtendedIterator;
    }

    public function getRequestIterator(): ConcurrentIterator {
        return $this->requestIterator;
    }

    public function isOpen(): bool {
        return $this->state === self::STATE_OPEN;
    }

    protected function dispatch(): void {
        $this->dispatcher = async(function (): void {
            try {
                while ($this->channelMessage->continue()) {
                    $message = $this->channelMessage->getValue();

                    if ($message instanceof ChannelWindowAdjust) {
                        $this->remoteWindow += $message->bytesToAdd;
                        $this->releaseWindowWaiter();
                    }

                    if ($message instanceof ChannelData) {
                        $this->consumeLocalWindow(\strlen($message->data));

                        // Never awaited: the connection read loop feeds this
                        // channel, so blocking here would stall every other
                        // channel behind one unread stream. The receive window
                        // above is what keeps the buffer bounded.
                        $this->dataQueue->pushAsync($message)->ignore();
                    }

                    if ($message instanceof ChannelExtendedData) {
                        $this->consumeLocalWindow(\strlen($message->data));
                        $this->dataExtendedQueue->pushAsync($message)->ignore();
                    }

                    if ($message instanceof ChannelRequest) {
                        $this->requestQueue->pushAsync($message)->ignore();
                    }

                    if ($message instanceof ChannelSuccess || $message instanceof ChannelFailure) {
                        $this->requestResultQueue->pushAsync($message)->ignore();
                    }

                    if ($message instanceof ChannelClose) {
                        // Answering is not optional, and it is what frees the
                        // channel on the peer's side. See sendClose().
                        $this->sendClose();
                        $this->doClose();

                        return;
                    }
                }

                $this->doClose();
            } catch (\Throwable $exception) {
                $this->doFail($exception);
            }
        });
    }

    public function open(): bool {
        $channelOpen = new ChannelOpen();
        $channelOpen->senderChannel = $this->channelId;
        $channelOpen->channelType = $this->getType();
        $channelOpen->initialWindowSize = self::LOCAL_WINDOW_SIZE;
        $channelOpen->maximumPacketSize = self::LOCAL_MAX_PACKET_SIZE;
        $channelOpen->extraData = $this->getOpenExtraData();

        $this->writer->write($channelOpen);

        if (!$this->channelMessage->continue()) {
            throw new ChannelException('Channel closed before the open could be confirmed');
        }

        $openResult = $this->channelMessage->getValue();

        if ($openResult instanceof ChannelOpenConfirmation) {
            // Everything we send from here on is addressed by the peer's number
            // for this channel, which is this and not necessarily ours.
            $this->peerChannelId = (int) $openResult->senderChannel;

            // The peer's limits were previously ignored entirely, so every
            // write went out as one packet of whatever size the caller passed.
            $this->remoteWindow = (int) $openResult->initialWindowSize;
            $this->remoteMaxPacket = ((int) $openResult->maximumPacketSize) ?: self::LOCAL_MAX_PACKET_SIZE;

            $this->state = self::STATE_OPEN;
            $this->dispatch();

            return true;
        }

        if ($openResult instanceof ChannelOpenFailure) {
            throw new ChannelException('Failed to open channel : ' . $openResult->description);
        }

        throw new ChannelException('Invalid message receive');
    }

    /**
     * Sends data to the peer, honouring its packet size and receive window.
     *
     * Both limits used to be ignored: the whole string went out as a single
     * CHANNEL_DATA message no matter how large, which overruns the maximum
     * packet size the peer announced and the window it granted.
     */
    public function data(string $data): void {
        $offset = 0;
        $length = \strlen($data);

        while ($offset < $length) {
            $window = $this->awaitRemoteWindow();
            $size = \min($length - $offset, $window, $this->maximumDataSize());

            $message = new ChannelData();
            $message->recipientChannel = $this->peerChannelId;
            $message->data = \substr($data, $offset, $size);

            $this->remoteWindow -= $size;
            $this->writer->write($message);

            $offset += $size;
        }
    }

    /**
     * Largest payload that still fits inside the peer's maximum packet size.
     */
    private function maximumDataSize(): int {
        return \max(1, $this->remoteMaxPacket - self::PACKET_HEADER_ALLOWANCE);
    }

    /**
     * Blocks until the peer has granted room, returning what is available.
     */
    private function awaitRemoteWindow(): int {
        while ($this->remoteWindow <= 0) {
            if ($this->state === self::STATE_FINISHED) {
                throw new ChannelException('Channel closed while waiting for the peer to extend its window');
            }

            $this->windowWaiter ??= new DeferredFuture();
            $this->windowWaiter->getFuture()->await();
        }

        return $this->remoteWindow;
    }

    private function releaseWindowWaiter(?\Throwable $reason = null): void {
        $waiter = $this->windowWaiter;
        $this->windowWaiter = null;

        if ($waiter === null) {
            return;
        }

        if ($reason === null) {
            $waiter->complete();

            return;
        }

        $waiter->error($reason);
    }

    /**
     * Accounts for data received and tops the window back up in good time.
     *
     * Replenishing at the halfway mark keeps a bulk transfer running: waiting
     * until the window is empty would stall the peer on every round trip.
     */
    private function consumeLocalWindow(int $bytes): void {
        $this->localWindow -= $bytes;

        if ($this->localWindow > (int) (self::LOCAL_WINDOW_SIZE / 2)) {
            return;
        }

        if ($this->state !== self::STATE_OPEN) {
            return;
        }

        $increment = self::LOCAL_WINDOW_SIZE - $this->localWindow;

        $adjust = new ChannelWindowAdjust();
        $adjust->recipientChannel = $this->peerChannelId;
        $adjust->bytesToAdd = $increment;

        $this->writer->write($adjust);

        $this->localWindow += $increment;
    }

    public function eof(): void {
        $message = new ChannelEof();
        $message->recipientChannel = $this->peerChannelId;

        $this->writer->write($message);
    }

    public function close(): void {
        if ($this->state === self::STATE_FINISHED) {
            return;
        }

        $this->sendClose();
        $this->doClose();
    }

    /**
     * Sends CHANNEL_CLOSE, at most once.
     *
     * RFC 4254 requires the side that receives a close to send one back unless
     * it has already sent its own, and answering was the half that was missing.
     * Without it the peer holds the channel half open for the life of the
     * connection: OpenSSH keeps the session slot, so after MaxSessions of them
     * - ten by default - every further channel is refused with "open failed"
     * and the connection looks like it has run out of something unnamed.
     *
     * A failed write is not worth reporting: it means the connection is already
     * gone, which is the state this message was asking for.
     */
    private function sendClose(): void {
        if ($this->closeSent) {
            return;
        }

        $this->closeSent = true;

        $message = new ChannelClose();
        $message->recipientChannel = $this->peerChannelId;

        try {
            $this->writer->write($message);
        } catch (\Throwable) {
            // Nothing left to close.
        }
    }

    public function __destruct() {
        if ($this->state !== self::STATE_OPEN || $this->closeSent) {
            return;
        }

        $this->closeSent = true;

        // Writing from a destructor must not touch $this: capturing it would
        // resurrect an object PHP is already collecting, and the write itself
        // may suspend. Capture only what the message needs and hand it to the
        // event loop.
        $writer = $this->writer;
        $message = new ChannelClose();
        $message->recipientChannel = $this->peerChannelId;

        $this->state = self::STATE_FINISHED;

        EventLoop::queue(static function () use ($writer, $message): void {
            try {
                $writer->write($message);
            } catch (\Throwable) {
                // Connection already gone; there is nothing left to close.
            }
        });
    }

    /**
     * End of stream: consumers see the queues complete.
     *
     * Idempotent on purpose. Both a user calling close() and the server sending
     * CHANNEL_CLOSE end up here, and completing an already completed Queue
     * throws an Error - which, being an Error rather than an Exception, slipped
     * straight past the catch in the v2 dispatch loop.
     */
    private function doClose(): void {
        if ($this->state === self::STATE_FINISHED) {
            return;
        }

        $this->state = self::STATE_FINISHED;

        // A writer blocked on the peer's window would otherwise wait forever.
        $this->releaseWindowWaiter(new ChannelException('Channel closed'));

        $this->requestResultQueue->complete();
        $this->requestQueue->complete();
        $this->dataQueue->complete();
        $this->dataExtendedQueue->complete();
    }

    /**
     * The connection died: pending requests must throw, streams merely end.
     *
     * Data queues complete rather than error so whatever already arrived can
     * still be read; a caller waiting on a request result, by contrast, has to
     * learn that no answer is ever coming.
     */
    private function doFail(\Throwable $reason): void {
        if ($this->state === self::STATE_FINISHED) {
            return;
        }

        $this->state = self::STATE_FINISHED;

        $this->releaseWindowWaiter($reason);

        $this->requestResultQueue->error($reason);
        $this->requestQueue->error($reason);
        $this->dataQueue->complete();
        $this->dataExtendedQueue->complete();
    }

    protected function doRequest(ChannelRequest $request, bool $needAck = true): bool {
        $this->writer->write($request);

        if (!$needAck) {
            return true;
        }

        if (!$this->requestResultIterator->continue()) {
            throw new ChannelException(\sprintf('Cannot advance on the channel iterator sending %s message', \get_class($request)));
        }

        $message = $this->requestResultIterator->getValue();

        if ($message instanceof ChannelFailure) {
            throw new ChannelFailureException('Request failure', $message);
        }

        if (!$message instanceof ChannelSuccess) {
            throw new ChannelException('Invalid message receive');
        }

        return true;
    }

    abstract protected function getType(): string;
}
