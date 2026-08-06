<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Channel;

use Amp\Cancellation;
use Amp\Pipeline\ConcurrentIterator;
use Amp\Pipeline\Queue;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Transport\BinaryPacketHandler;
use Revolt\EventLoop;

/**
 * A transport that is driven by the test instead of by a socket.
 *
 * Lets the channel lifecycle be exercised without a server: messages can be
 * queued up, the connection can be dropped (read() returns null) or made to
 * fail outright, and everything written is recorded.
 */
final class FakeHandler implements BinaryPacketHandler {
    /** @var array<int, Message|string> */
    public array $written = [];

    public bool $closed = false;

    private Queue $incoming;

    private ConcurrentIterator $iterator;

    private ?\Throwable $readFailure = null;

    private ?string $keepAlive = null;

    public function __construct() {
        $this->incoming = new Queue();
        $this->iterator = $this->incoming->iterate();

        // A real transport owns a socket watcher, which is what keeps the event
        // loop referenced while every fiber sits waiting. This double reads
        // from a queue instead, so without a referenced watcher of its own the
        // loop would consider itself idle and abort any pending suspension -
        // including a TimeoutCancellation, whose own timer is unreferenced by
        // design. Emulate the socket's hold on the loop.
        $this->keepAlive = EventLoop::repeat(1, static function (): void {
        });
    }

    public function __destruct() {
        $this->releaseLoop();
    }

    private function releaseLoop(): void {
        if ($this->keepAlive !== null) {
            EventLoop::cancel($this->keepAlive);
            $this->keepAlive = null;
        }
    }

    /** Queue a message for the dispatcher to route. */
    public function deliver(Message $message): void {
        $this->incoming->pushAsync($message)->ignore();
    }

    /** The peer went away: the next read() returns null. */
    public function disconnect(): void {
        $this->incoming->complete();
    }

    /** The transport itself blows up, e.g. a bad MAC. */
    public function failWith(\Throwable $reason): void {
        $this->readFailure = $reason;
        $this->incoming->complete();
    }

    public function read(?Cancellation $cancellation = null): Message|string|null {
        if (!$this->iterator->continue($cancellation)) {
            if ($this->readFailure !== null) {
                throw $this->readFailure;
            }

            return null;
        }

        return $this->iterator->getValue();
    }

    public function write(Message|string $message): void {
        $this->written[] = $message;
    }

    public function close(): void {
        $this->closed = true;
        $this->releaseLoop();
    }

    public function updateDecryption(Decryption $decryption, Mac $decryptMac): void {
    }

    public function updateEncryption(Encryption $encryption, Mac $encryptMac): void {
    }
}
