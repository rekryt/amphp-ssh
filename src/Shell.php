<?php declare(strict_types=1);

namespace Amp\Ssh;

use function Amp\async;
use Amp\ByteStream\ReadableStream;
use Amp\ByteStream\WritableStream;
use Amp\Cancellation;
use Amp\DeferredFuture;
use Amp\Future;
use Amp\Ssh\Channel\ChannelInputStream;
use Amp\Ssh\Channel\ChannelOutputStream;
use Amp\Ssh\Message\ChannelRequestExitStatus;

class Shell {
    /** @see Process::SIGKILL */
    private const SIGKILL = 9;

    private Channel\Session $session;

    private ChannelInputStream $stderr;

    private ChannelInputStream $stdout;

    private ChannelOutputStream $stdin;

    private int|false|null $exitCode = null;

    private ?\Throwable $failure = null;

    private bool $finished = false;

    private ?DeferredFuture $deferred = null;

    private array $env;

    private ?Future $requestHandler = null;

    public function __construct(SshResource $sshResource, array $env = []) {
        $this->session = $sshResource->createSession();
        $this->stdout = new ChannelInputStream($this->session->getDataIterator());
        $this->stderr = new ChannelInputStream($this->session->getDataExtendedIterator());
        $this->stdin = new ChannelOutputStream($this->session);
        $this->env = $env;

        $this->handleRequests();
    }

    /**
     * @see Process::join()
     */
    public function join(?Cancellation $cancellation = null): int|false {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        if ($this->exitCode !== null) {
            return $this->exitCode;
        }

        if ($this->deferred === null) {
            throw new StatusError('Shell is not running');
        }

        return $this->deferred->getFuture()->await($cancellation);
    }

    public function start(int $columns = 80, int $rows = 24, int $width = 800, int $height = 600): void {
        if ($this->deferred !== null) {
            throw new StatusError('Shell has already been started.');
        }

        if ($this->finished) {
            throw new StatusError('Shell channel is already closed.');
        }

        $this->deferred = new DeferredFuture();

        try {
            $this->session->open();

            foreach ($this->env as $key => $value) {
                $this->session->env((string) $key, (string) $value, true);
            }

            $this->session->pty($columns, $rows, $width, $height);
            $this->session->shell();
        } catch (\Throwable $exception) {
            $this->deferred = null;

            throw $exception;
        }
    }

    public function changeWindowSize(int $columns = 80, int $rows = 24, int $width = 800, int $height = 600): void {
        if (!$this->isRunning()) {
            throw new StatusError('Shell is not running.');
        }

        $this->session->changeWindowSize($columns, $rows, $width, $height);
    }

    public function kill(): void {
        $this->signal(self::SIGKILL);
    }

    public function signal(int $signo): void {
        if (!$this->isRunning()) {
            throw new StatusError('Shell is not running.');
        }

        $this->session->signal($signo);
    }

    public function isRunning(): bool {
        return $this->deferred !== null && !$this->finished;
    }

    public function getStdin(): WritableStream {
        return $this->stdin;
    }

    public function getStdout(): ReadableStream {
        return $this->stdout;
    }

    public function getStderr(): ReadableStream {
        return $this->stderr;
    }

    /**
     * @see Process::handleRequests()
     *
     * The v2 version broke out of this loop after the exit status. Under v3
     * that releases the iterator, which disposes the queue and makes the
     * channel's next push fail, so the loop now always runs to the end.
     */
    private function handleRequests(): void {
        $this->requestHandler = async(function (): void {
            $iterator = $this->session->getRequestIterator();

            try {
                while ($iterator->continue()) {
                    $message = $iterator->getValue();

                    if ($message instanceof ChannelRequestExitStatus) {
                        $this->complete($message->code);
                    }
                }

                // Some servers never send an exit status.
                $this->complete(false);
            } catch (\Throwable $exception) {
                $this->fail($exception);
            }
        });
    }

    private function complete(int|false $exitCode): void {
        if ($this->finished) {
            return;
        }

        $this->finished = true;
        $this->exitCode = $exitCode;
        $this->deferred?->complete($exitCode);
    }

    private function fail(\Throwable $exception): void {
        if ($this->finished) {
            return;
        }

        $this->finished = true;
        $this->failure = $exception;

        if ($this->deferred !== null) {
            $this->deferred->error($exception);
            $this->deferred->getFuture()->ignore();
        }
    }
}
