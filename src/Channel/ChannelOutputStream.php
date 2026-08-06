<?php declare(strict_types=1);

namespace Amp\Ssh\Channel;

use Amp\ByteStream\ClosedException;
use Amp\ByteStream\WritableStream;
use Amp\DeferredFuture;

/**
 * Adapts a channel to a writable stream, i.e. the remote process's stdin.
 *
 * @internal
 */
final class ChannelOutputStream implements WritableStream {
    private bool $writable = true;

    private Channel $channel;

    private DeferredFuture $onClose;

    public function __construct(Channel $channel) {
        $this->channel = $channel;
        $this->onClose = new DeferredFuture();
    }

    /**
     * Returning does not mean the peer received the data: the packet is handed
     * to the transport, which flushes it through the event loop.
     *
     * @throws ClosedException If the stream was already ended or closed. The v2
     *                         implementation silently discarded such writes,
     *                         which hid writes to a process that had exited.
     */
    public function write(string $bytes): void {
        if (!$this->writable) {
            throw new ClosedException('The stream is no longer writable');
        }

        $this->channel->data($bytes);
    }

    /**
     * Signals EOF to the remote end while leaving the channel open, so the
     * process can still produce output on stdout and stderr.
     */
    public function end(): void {
        if (!$this->writable) {
            return;
        }

        $this->writable = false;
        $this->channel->eof();
        $this->onClose->complete();
    }

    public function isWritable(): bool {
        return $this->writable;
    }

    public function close(): void {
        $this->end();
    }

    public function isClosed(): bool {
        return !$this->writable;
    }

    public function onClose(\Closure $onClose): void {
        $this->onClose->getFuture()->finally($onClose);
    }
}
