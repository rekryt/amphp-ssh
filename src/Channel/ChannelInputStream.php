<?php declare(strict_types=1);

namespace Amp\Ssh\Channel;

use Amp\ByteStream\ReadableStream;
use Amp\ByteStream\ReadableStreamIteratorAggregate;
use Amp\Cancellation;
use Amp\DeferredFuture;
use Amp\Pipeline\ConcurrentIterator;
use Amp\Ssh\Message\ChannelData;
use Amp\Ssh\Message\ChannelExtendedData;

/**
 * Adapts one of a channel's data queues to a readable stream.
 *
 * @implements \IteratorAggregate<int, string>
 *
 * @internal
 */
final class ChannelInputStream implements ReadableStream, \IteratorAggregate {
    use ReadableStreamIteratorAggregate;

    private bool $readable = true;

    private ConcurrentIterator $iterator;

    private DeferredFuture $onClose;

    public function __construct(ConcurrentIterator $iterator) {
        $this->iterator = $iterator;
        $this->onClose = new DeferredFuture();
    }

    public function read(?Cancellation $cancellation = null): ?string {
        if (!$this->readable) {
            return null;
        }

        if (!$this->iterator->continue($cancellation)) {
            $this->close();

            return null;
        }

        $message = $this->iterator->getValue();

        if ($message instanceof ChannelData || $message instanceof ChannelExtendedData) {
            return $message->data;
        }

        return $message;
    }

    public function isReadable(): bool {
        return $this->readable;
    }

    /**
     * Marks this side as finished without disposing the queue.
     *
     * The channel owns the queue and the iterator; disposing here would break
     * the producer for every other consumer of the same channel.
     */
    public function close(): void {
        if (!$this->readable) {
            return;
        }

        $this->readable = false;
        $this->onClose->complete();
    }

    public function isClosed(): bool {
        return !$this->readable;
    }

    public function onClose(\Closure $onClose): void {
        $this->onClose->getFuture()->finally($onClose);
    }
}
