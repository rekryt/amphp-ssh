<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use function Amp\async;
use Amp\Ssh\Channel\ChannelException;
use Amp\Ssh\Shell;
use Amp\Ssh\StatusError;
use Amp\TimeoutCancellation;
use Revolt\EventLoop;

class ShellTest extends IntegrationTestCase {
    /**
     * Reads the shell's output until the marker shows up, so the assertion does
     * not depend on how the server chunks it.
     */
    private function readUntil(Shell $shell, string $needle, float $timeout = 10): string {
        $cancellation = new TimeoutCancellation($timeout);
        $output = '';

        while (($chunk = $shell->getStdout()->read($cancellation)) !== null) {
            $output .= $chunk;

            if (\str_contains($output, $needle)) {
                break;
            }
        }

        return $output;
    }

    public function testShell() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start();
        $shell->getStdin()->write("echo foo; exit\n");

        self::assertTrue($shell->isRunning());

        $output = $this->readUntil($shell, 'foo');
        $exitCode = $shell->join();

        self::assertFalse($shell->isRunning());
        self::assertStringContainsString('foo', $output);
        self::assertSame(0, $exitCode);

        $ssh->close();
    }

    public function testShellNotStartedOnJoin() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $this->expectException(StatusError::class);

        try {
            $shell->join();
        } finally {
            $ssh->close();
        }
    }

    public function testShellNotStartedOnSignal() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $this->expectException(StatusError::class);

        try {
            $shell->signal(9);
        } finally {
            $ssh->close();
        }
    }

    public function testShellAlreadyStarted() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start();

        $this->expectException(StatusError::class);

        try {
            $shell->start();
        } finally {
            $ssh->close();
        }
    }

    public function testShellEnv() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh, ['FOO' => 'bar']);

        $shell->start();

        self::assertTrue($shell->isRunning());

        $shell->getStdin()->write("echo \$FOO; exit\n");

        $output = $this->readUntil($shell, 'bar');
        $exitCode = $shell->join();

        self::assertFalse($shell->isRunning());
        self::assertStringContainsString('bar', $output);
        self::assertSame(0, $exitCode);

        // join() is repeatable.
        self::assertSame(0, $shell->join());

        $ssh->close();
    }

    /**
     * "0" is falsy in PHP; writing and reading it must not be mistaken for EOF.
     */
    public function testStdInZero() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start();

        async(fn () => $shell->join());

        $this->readUntil($shell, ':~#');

        $shell->getStdin()->write('1');
        self::assertSame('1', $shell->getStdout()->read(new TimeoutCancellation(10)));

        $shell->getStdin()->write('0');
        self::assertSame('0', $shell->getStdout()->read(new TimeoutCancellation(10)));

        $ssh->close();
    }

    public function testShellStartWindowSize() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start(120, 39);

        self::assertTrue($shell->isRunning());

        $shell->getStdin()->write("stty size; exit\n");

        $output = $this->readUntil($shell, '39 120');
        $exitCode = $shell->join();

        self::assertFalse($shell->isRunning());
        self::assertStringContainsString('39 120', $output);
        self::assertSame(0, $exitCode);

        $ssh->close();
    }

    public function testShellChangeWindowSize() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start();

        self::assertTrue($shell->isRunning());

        $shell->changeWindowSize(120, 39);
        $shell->getStdin()->write("stty size; exit\n");

        $output = $this->readUntil($shell, '39 120');
        $exitCode = $shell->join();

        self::assertFalse($shell->isRunning());
        self::assertStringContainsString('39 120', $output);
        self::assertSame(0, $exitCode);

        $ssh->close();
    }

    public function testShellFailOnDisconnect() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start();

        self::assertTrue($shell->isRunning());

        EventLoop::queue(static fn () => NetworkHelper::disconnect($ssh));

        $this->expectException(ChannelException::class);

        $shell->join();
    }

    public function testShellFinishWithFalseOnChannelClose() {
        $ssh = $this->getSsh();
        $shell = new Shell($ssh);

        $shell->start();

        self::assertTrue($shell->isRunning());

        EventLoop::queue(static fn () => $ssh->close());

        self::assertFalse($shell->join());
    }
}
