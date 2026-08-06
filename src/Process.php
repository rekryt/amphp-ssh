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

class Process {
    /**
     * SIGKILL, spelled out because the constant only exists with ext-pcntl,
     * which this package does not require. Referencing it directly made kill()
     * fatal on any build without that extension.
     */
    private const SIGKILL = 9;

    private Channel\Session $session;

    private string $command;

    private ChannelInputStream $stderr;

    private ChannelInputStream $stdout;

    private ChannelOutputStream $stdin;

    private int|false|null $exitCode = null;

    private ?\Throwable $failure = null;

    private bool $finished = false;

    private ?DeferredFuture $deferred = null;

    private bool $open = false;

    private array $env;

    private ?Future $requestHandler = null;

    /**
     * @param string|null $cwd Directory to run in, taken literally: it is
     *                         quoted for the remote shell, so a space or a
     *                         quote in it is part of the name and a semicolon
     *                         cannot start a command of its own. Nothing in it
     *                         is expanded either, so "~" and "$HOME" are
     *                         directory names rather than your home directory -
     *                         leave $cwd null to run there.
     *                         The command keeps its own meaning: it is shell
     *                         text and is not quoted.
     */
    public function __construct(SshResource $sshResource, string $command, ?string $cwd = null, array $env = []) {
        $this->session = $sshResource->createSession();

        // && rather than ;, so a directory that cannot be entered stops the
        // command instead of running it wherever the login started.
        $this->command = $cwd !== null
            ? \sprintf('cd %s && %s', self::quote($cwd), $command)
            : $command;
        $this->stdout = new ChannelInputStream($this->session->getDataIterator());
        $this->stderr = new ChannelInputStream($this->session->getDataExtendedIterator());
        $this->stdin = new ChannelOutputStream($this->session);
        $this->env = $env;

        $this->handleRequests();
    }

    /**
     * Wraps a value so the remote shell reads it as one literal word.
     *
     * Single quotes suspend every kind of expansion a POSIX shell performs,
     * and the only character they cannot hold is the single quote itself -
     * which is closed, escaped and reopened, the usual '\'' dance.
     *
     * escapeshellarg() cannot be used for this. It quotes for the platform PHP
     * is running on, and on Windows that means double quotes and a different
     * set of rules altogether - while the string is going to be read by a shell
     * on the other end of the connection, which is a POSIX one.
     */
    private static function quote(string $value): string {
        return "'" . \str_replace("'", "'\\''", $value) . "'";
    }

    public function start(): void {
        if ($this->deferred !== null) {
            throw new StatusError('Process has already been started.');
        }

        if ($this->finished) {
            throw new StatusError('Process channel is already closed.');
        }

        $this->deferred = new DeferredFuture();

        try {
            if (!$this->open) {
                $this->session->open();

                $this->open = true;
            }

            foreach ($this->env as $key => $value) {
                $this->session->env((string) $key, (string) $value);
            }

            $this->session->exec($this->command);
        } catch (\Throwable $exception) {
            $this->deferred = null;

            throw $exception;
        }
    }

    /**
     * Wait for the remote process to exit.
     *
     * Returns the exit status, or false when the server closed the channel
     * without sending one.
     *
     * Cancelling detaches this caller and nothing else: the process keeps
     * running, the channel stays open, and calling join() again waits for the
     * same result. Terminating the process is an explicit signal()/kill().
     */
    public function join(?Cancellation $cancellation = null): int|false {
        if ($this->failure !== null) {
            throw $this->failure;
        }

        if ($this->exitCode !== null) {
            return $this->exitCode;
        }

        if ($this->deferred === null) {
            throw new StatusError('Process has not been started.');
        }

        return $this->deferred->getFuture()->await($cancellation);
    }

    public function kill(): void {
        $this->signal(self::SIGKILL);
    }

    public function signal(int $signo): void {
        if (!$this->isRunning()) {
            throw new StatusError('Process is not running.');
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
     * Watch the channel for the exit status.
     *
     * Runs for the whole life of the channel and deliberately never breaks out
     * of the loop: abandoning the iterator early would dispose the queue and
     * make the channel's producer fail.
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

            // join() rethrows from $failure, so nobody may ever await this
            // future. Without ignore() an unawaited errored future reports an
            // UnhandledFutureError to the event loop when it is collected.
            $this->deferred->getFuture()->ignore();
        }
    }
}
