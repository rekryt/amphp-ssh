<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use function Amp\async;
use Amp\ByteStream;
use Amp\CancelledException;
use Amp\Future;
use Amp\Ssh\Channel\ChannelException;
use Amp\Ssh\Channel\SessionEnvException;
use Amp\Ssh\Process;
use Amp\Ssh\StatusError;
use Amp\TimeoutCancellation;
use Revolt\EventLoop;

class ProcessTest extends IntegrationTestCase {
    public function testProcess() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'echo foo');

        $process->start();

        self::assertTrue($process->isRunning());

        $exitCode = $process->join();
        $output = ByteStream\buffer($process->getStdout());

        self::assertFalse($process->isRunning());
        self::assertSame("foo\n", $output);
        self::assertSame(0, $exitCode);

        $ssh->close();
    }

    public function testProcessNotStartedOnJoin() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'echo foo');

        $this->expectException(StatusError::class);

        try {
            $process->join();
        } finally {
            $ssh->close();
        }
    }

    public function testProcessNotStartedOnSignal() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'echo foo');

        $this->expectException(StatusError::class);

        try {
            $process->signal(9);
        } finally {
            $ssh->close();
        }
    }

    public function testProcessAlreadyStarted() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'echo foo');

        $process->start();

        $this->expectException(StatusError::class);

        try {
            $process->start();
        } finally {
            $ssh->close();
        }
    }

    public function testProcessEnv() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'echo $FOO', null, ['FOO' => 'bar']);

        try {
            $process->start();
        } catch (SessionEnvException $exception) {
            $ssh->close();

            // AcceptEnv decides this, and only the test container is set up to
            // allow FOO; a stock sshd allows little beyond LANG and LC_*. The
            // refusal itself is what testProcessBadEnv asserts on, so a server
            // that says no leaves nothing here to prove.
            self::markTestSkipped('This server does not accept the FOO environment variable (AcceptEnv).');
        }

        self::assertTrue($process->isRunning());

        $exitCode = $process->join();
        $output = ByteStream\buffer($process->getStdout());

        self::assertFalse($process->isRunning());
        self::assertSame("bar\n", $output);
        self::assertSame(0, $exitCode);

        // join() is repeatable and keeps returning the same result.
        self::assertSame(0, $process->join());

        $ssh->close();
    }

    public function testProcessBadEnv() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'echo $FOO2', null, ['FOO2' => 'bar']);

        $this->expectException(SessionEnvException::class);

        try {
            $process->start();
        } finally {
            $ssh->close();
        }
    }

    public function testSignal() {
        self::markTestSkipped('OpenSSH does not support receiving signal');
    }

    public function testStdin() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'read foo; echo $foo');

        $process->start();

        self::assertTrue($process->isRunning());

        $process->getStdin()->write("bar\n");

        $exitCode = $process->join();
        $output = ByteStream\buffer($process->getStdout());

        self::assertFalse($process->isRunning());
        self::assertSame("bar\n", $output);
        self::assertSame(0, $exitCode);

        $ssh->close();
    }

    public function testStderr() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, '>&2 echo foo');

        $process->start();

        self::assertTrue($process->isRunning());

        $exitCode = $process->join();
        $output = ByteStream\buffer($process->getStderr());

        self::assertFalse($process->isRunning());
        self::assertSame("foo\n", $output);
        self::assertSame(0, $exitCode);

        $ssh->close();
    }

    /**
     * A connection dropped underneath a running process is an error, not an
     * orderly end.
     */
    public function testProcessFailOnDisconnect() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'sleep 10; echo test;');

        $process->start();

        self::assertTrue($process->isRunning());

        EventLoop::queue(static fn () => NetworkHelper::disconnect($ssh));

        $this->expectException(ChannelException::class);

        $process->join();
    }

    /**
     * A channel closed without an exit status resolves to false: some servers
     * simply never send one.
     */
    public function testProcessFinishWithFalseOnChannelClose() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'sleep 10; echo test;');

        $process->start();

        self::assertTrue($process->isRunning());

        EventLoop::queue(static fn () => $ssh->close());

        self::assertFalse($process->join());
    }

    /**
     * Cancelling a join detaches the caller only: the remote process keeps
     * running and a later join still observes its exit status.
     */
    public function testCancellingJoinLeavesProcessRunning() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'sleep 1; echo done');

        $process->start();

        try {
            $process->join(new TimeoutCancellation(0.1));
            self::fail('Expected the join to be cancelled');
        } catch (CancelledException) {
            // expected
        }

        self::assertTrue($process->isRunning(), 'Cancelling join() must not kill the process');
        self::assertSame(0, $process->join(new TimeoutCancellation(10)));

        $ssh->close();
    }

    /**
     * Several processes must be able to share one connection.
     *
     * Channel multiplexing had no coverage at all before, even though it is the
     * entire point of the dispatcher.
     */
    public function testConcurrentProcessesOnOneConnection() {
        $ssh = $this->getSsh();

        $processes = [];

        foreach (['echo one', 'echo two', 'echo three'] as $command) {
            $process = new Process($ssh, $command);
            $process->start();
            $processes[] = $process;
        }

        $outputs = Future\await(\array_map(
            static fn (Process $process) => async(static function () use ($process): string {
                $process->join();

                return ByteStream\buffer($process->getStdout());
            }),
            $processes
        ));

        self::assertSame(["one\n", "two\n", "three\n"], $outputs);

        $ssh->close();
    }

    /**
     * One process whose output nobody reads must not stall another.
     *
     * On v2 the dispatcher awaited every emit, so an unread stdout blocked the
     * single read loop and with it every other channel on the connection.
     */
    public function testUnreadOutputDoesNotStallAnotherProcess() {
        $ssh = $this->getSsh();

        $ignored = new Process($ssh, 'head -c 200000 /dev/zero');
        $ignored->start();

        $active = new Process($ssh, 'echo still-moving');
        $active->start();

        self::assertSame(0, $active->join(new TimeoutCancellation(10)));
        self::assertSame("still-moving\n", ByteStream\buffer($active->getStdout()));

        $ssh->close();
    }

    /**
     * The exit status can arrive before the output has been consumed; the
     * buffered output must still be readable in full afterwards.
     */
    public function testOutputIsCompleteAfterExitStatus() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'seq 1 500');

        $process->start();

        self::assertSame(0, $process->join());

        $output = ByteStream\buffer($process->getStdout());
        $lines = \explode("\n", \trim($output));

        self::assertCount(500, $lines);
        self::assertSame('1', $lines[0]);
        self::assertSame('500', $lines[499]);

        $ssh->close();
    }

    /**
     * A write far larger than the peer's maximum packet size must survive the
     * round trip intact, which means it has to be split and paced against the
     * window rather than shoved out as one oversized message.
     */
    public function testLargeStdinWrite() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'cat');

        $process->start();

        $payload = \str_repeat('0123456789abcdef', 64 * 1024); // 1 MiB

        $process->getStdin()->write($payload);
        $process->getStdin()->end();

        $output = ByteStream\buffer($process->getStdout());

        self::assertSame(\strlen($payload), \strlen($output));
        self::assertSame($payload, $output);
        self::assertSame(0, $process->join(new TimeoutCancellation(30)));

        $ssh->close();
    }

    /**
     * Reading far more than the advertised receive window only works if the
     * client keeps topping that window back up.
     */
    public function testLargeStdoutRead() {
        $ssh = $this->getSsh();
        $process = new Process($ssh, 'head -c 5000000 /dev/zero');

        $process->start();

        $output = ByteStream\buffer($process->getStdout());

        self::assertSame(5000000, \strlen($output));
        self::assertSame(0, $process->join(new TimeoutCancellation(30)));

        $ssh->close();
    }
}
