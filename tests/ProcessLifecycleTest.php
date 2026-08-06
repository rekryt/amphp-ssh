<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use Amp\ByteStream\ClosedException;
use Amp\CancelledException;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Channel\ChannelException;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Message\ChannelClose;
use Amp\Ssh\Message\ChannelOpen;
use Amp\Ssh\Message\ChannelOpenConfirmation;
use Amp\Ssh\Message\ChannelRequestExec;
use Amp\Ssh\Message\ChannelRequestExitStatus;
use Amp\Ssh\Message\ChannelSuccess;
use Amp\Ssh\Process;
use Amp\Ssh\SshResource;
use Amp\Ssh\StatusError;
use Amp\Ssh\Tests\Channel\FakeHandler;
use Amp\TimeoutCancellation;

/**
 * Process semantics without a server.
 *
 * Covers the two things the public API promises and the migration could
 * silently break: how join() reports the outcome (status, false, or a thrown
 * ChannelException), and that cancelling a join() only detaches the caller
 * rather than touching the process or the channel.
 */
class ProcessLifecycleTest extends AsyncTestCase {
    private FakeHandler $handler;

    private Dispatcher $dispatcher;

    private SshResource $resource;

    protected function setUp(): void {
        parent::setUp();

        $this->handler = new FakeHandler();
        $this->dispatcher = new Dispatcher($this->handler);
        $this->dispatcher->start();
        $this->resource = new SshResource($this->handler, $this->dispatcher);
    }

    /**
     * Feeds the replies a session needs to reach a running state: the open
     * confirmation, then one success per channel request exec() issues.
     */
    private function startProcess(string $command = 'echo foo', array $env = [], ?string $cwd = null): Process {
        $process = new Process($this->resource, $command, $cwd, $env);

        $confirmation = new ChannelOpenConfirmation();
        $confirmation->recipientChannel = 0;
        $confirmation->senderChannel = 0;
        $confirmation->initialWindowSize = 0x7FFFFFFF;
        $confirmation->maximumPacketSize = 0x4000;
        $this->handler->deliver($confirmation);

        // One acknowledgement per env var, plus one for exec itself.
        for ($i = 0; $i <= \count($env); ++$i) {
            $success = new ChannelSuccess();
            $success->recipientChannel = 0;
            $this->handler->deliver($success);
        }

        $process->start();

        return $process;
    }

    /**
     * The exec request as it actually went out on the wire.
     */
    private function execRequest(): ChannelRequestExec {
        foreach ($this->handler->written as $message) {
            if ($message instanceof ChannelRequestExec) {
                return $message;
            }
        }

        self::fail('No exec request was written');
    }

    private function execCommand(): string {
        return $this->execRequest()->command;
    }

    /**
     * Every message we send carries the peer's number for the channel.
     *
     * Each side numbers its own end of a channel and the two need not agree.
     * Sending our own number back works for as long as they happen to match -
     * which they do for the first channel on a connection, and stop doing once
     * one has been closed and another opened, because a server may reuse the
     * number it just freed while we have moved on to the next. The symptom is
     * not a broken channel but a dropped connection: the server is being asked
     * about a channel it does not have.
     */
    public function testMessagesAreAddressedByThePeersChannelNumber(): void {
        $process = new Process($this->resource, 'echo foo');

        $confirmation = new ChannelOpenConfirmation();
        // Our number for the channel...
        $confirmation->recipientChannel = 0;
        // ...and the server's, which is what we have to address it by.
        $confirmation->senderChannel = 7;
        $confirmation->initialWindowSize = 0x7FFFFFFF;
        $confirmation->maximumPacketSize = 0x4000;
        $this->handler->deliver($confirmation);

        $success = new ChannelSuccess();
        $success->recipientChannel = 0;
        $this->handler->deliver($success);

        $process->start();

        self::assertSame(7, $this->execRequest()->recipientChannel);

        // The open request is the one message that carries our own number,
        // because that is what the peer will address us by.
        foreach ($this->handler->written as $message) {
            if ($message instanceof ChannelOpen) {
                self::assertSame(0, $message->senderChannel);

                return;
            }
        }

        self::fail('No channel open was written');
    }

    public function testCommandGoesOutUnchangedWithoutAWorkingDirectory(): void {
        $this->startProcess('rm -rf build');

        self::assertSame('rm -rf build', $this->execCommand());
    }

    /**
     * A working directory is quoted and joined with &&.
     *
     * With a semicolon there instead, a directory that cannot be entered left
     * `cd` to fail and the command to run anyway, in whatever directory the
     * login started in. For `rm -rf build` that is not a cosmetic difference.
     */
    public function testWorkingDirectoryIsJoinedSoAFailedCdStopsTheCommand(): void {
        $this->startProcess('rm -rf build', [], '/srv/app');

        self::assertSame("cd '/srv/app' && rm -rf build", $this->execCommand());
    }

    /**
     * A path is a path, whatever it happens to contain.
     *
     * It used to be pasted in raw, so a space split it into two arguments and
     * a semicolon started a command of its own - on the far end, as whoever
     * the connection authenticated as.
     */
    public function testWorkingDirectoryCannotRunCommandsOfItsOwn(): void {
        $this->startProcess('pwd', [], '/srv/app; rm -rf /');

        self::assertSame("cd '/srv/app; rm -rf /' && pwd", $this->execCommand());
    }

    public function testWorkingDirectoryWithASpaceStaysOneArgument(): void {
        $this->startProcess('pwd', [], '/srv/my app');

        self::assertSame("cd '/srv/my app' && pwd", $this->execCommand());
    }

    /**
     * The single quote is the one character single quoting cannot contain, so
     * it is closed, escaped and reopened.
     */
    public function testWorkingDirectoryWithAQuoteInIt(): void {
        $this->startProcess('pwd', [], "/srv/it's");

        self::assertSame("cd '/srv/it'\\''s' && pwd", $this->execCommand());
    }

    /**
     * Nothing in the path is expanded, which is the price of quoting it.
     */
    public function testWorkingDirectoryIsNotExpanded(): void {
        $this->startProcess('pwd', [], '$HOME/app');

        self::assertSame("cd '\$HOME/app' && pwd", $this->execCommand());
    }

    /**
     * A close from the server is answered with one of our own, exactly once.
     *
     * RFC 4254 makes the reply mandatory, and it is what releases the channel
     * on the peer's side. Without it OpenSSH holds the session slot for the
     * life of the connection, so the eleventh command on a connection - one
     * past the default MaxSessions - fails to open a channel at all, on a
     * connection that is otherwise perfectly healthy.
     */
    public function testAServerInitiatedCloseIsAnsweredOnce(): void {
        $process = $this->startProcess();

        $close = new ChannelClose();
        $close->recipientChannel = 0;
        $this->handler->deliver($close);

        $process->join();

        $closes = \array_filter(
            $this->handler->written,
            static fn ($message): bool => $message instanceof ChannelClose
        );

        self::assertCount(1, $closes, 'Expected exactly one CHANNEL_CLOSE to be written');
    }

    private function exitStatus(int $code): ChannelRequestExitStatus {
        $message = new ChannelRequestExitStatus();
        $message->recipientChannel = 0;
        $message->code = $code;

        return $message;
    }

    public function testJoinReturnsExitStatus() {
        $process = $this->startProcess();

        self::assertTrue($process->isRunning());

        $this->handler->deliver($this->exitStatus(0));

        self::assertSame(0, $process->join());
        self::assertFalse($process->isRunning());
    }

    public function testJoinIsRepeatable() {
        $process = $this->startProcess();
        $this->handler->deliver($this->exitStatus(7));

        self::assertSame(7, $process->join());
        self::assertSame(7, $process->join());
    }

    /**
     * A server that closes the channel without an exit status is not an error.
     */
    public function testJoinReturnsFalseWhenChannelClosesWithoutStatus() {
        $process = $this->startProcess();

        $close = new ChannelClose();
        $close->recipientChannel = 0;
        $this->handler->deliver($close);

        self::assertFalse($process->join());
    }

    public function testJoinThrowsWhenConnectionIsLost() {
        $process = $this->startProcess();

        $this->handler->disconnect();

        $this->expectException(ChannelException::class);

        $process->join();
    }

    /**
     * The rule the whole cancellation story rests on: cancelling a wait does
     * not change any SSH state.
     */
    public function testCancellingJoinLeavesTheProcessRunning() {
        $process = $this->startProcess('sleep 10');

        try {
            $process->join(new TimeoutCancellation(0.05));
            self::fail('Expected the join to be cancelled');
        } catch (CancelledException) {
            // expected
        }

        self::assertTrue($process->isRunning(), 'Cancelling join() must not kill the process');

        $this->handler->deliver($this->exitStatus(0));

        self::assertSame(0, $process->join(), 'A later join() must still see the result');
    }

    public function testJoinBeforeStart() {
        $process = new Process($this->resource, 'echo foo');

        $this->expectException(StatusError::class);

        $process->join();
    }

    public function testDoubleStart() {
        $process = $this->startProcess();

        $this->expectException(StatusError::class);

        $process->start();
    }

    public function testSignalBeforeStart() {
        $process = new Process($this->resource, 'echo foo');

        $this->expectException(StatusError::class);

        $process->signal(9);
    }

    /**
     * v2 silently discarded writes to a finished process; that hid real bugs.
     */
    public function testWritingToStdinAfterEndThrows() {
        $process = $this->startProcess();

        $process->getStdin()->end();

        $this->expectException(ClosedException::class);

        $process->getStdin()->write('too late');
    }

    public function testEnvVarsAreRequestedBeforeExec() {
        $process = $this->startProcess('echo $FOO', ['FOO' => 'bar']);

        $this->handler->deliver($this->exitStatus(0));

        self::assertSame(0, $process->join());

        $types = \array_map(
            static fn ($message) => \is_object($message) ? \get_class($message) : \gettype($message),
            $this->handler->written
        );

        $envIndex = \array_search(\Amp\Ssh\Message\ChannelRequestEnv::class, $types, true);
        $execIndex = \array_search(\Amp\Ssh\Message\ChannelRequestExec::class, $types, true);

        self::assertNotFalse($envIndex, 'The env request must be sent');
        self::assertNotFalse($execIndex, 'The exec request must be sent');
        self::assertLessThan($execIndex, $envIndex, 'env must be set before exec');
    }
}
