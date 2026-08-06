<?php declare(strict_types=1);

// Timeouts, cancellation, and what it actually takes to stop a remote command.
//
// Cancellation means two different things here, and mixing them up is the
// most common way to be surprised by this library:
//
//   - During connect() it is fatal and clean. A half negotiated connection
//     cannot be resumed, so the socket is closed before the exception leaves.
//   - After connect() it is local to the caller. Cancelling join() detaches
//     this fiber from the wait. Nothing is sent to the server, the command
//     keeps running, and calling join() again waits for the same result.
//
// Stopping the command is a separate problem, and a harder one than it looks:
// see the third section.

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\CancelledException;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;
use Amp\TimeoutCancellation;

// A connect timeout covers the TCP connection, the key exchange, the host key
// check and the authentication - everything up to a usable connection.
$ssh = connect(
    $target,
    new PublicKey($username, $keyPath),
    cancellation: new TimeoutCancellation(15)
);

echo '--- cancelling a wait ---', PHP_EOL;

$process = new Process($ssh, 'sleep 5; echo the command ran to the end');
$process->start();

try {
    $process->join(new TimeoutCancellation(2));

    echo 'Finished within the timeout.', PHP_EOL;
} catch (CancelledException) {
    echo 'Waited 2s and gave up.', PHP_EOL;
}

// The wait was abandoned, not the command.
\printf('Still running on the server: %s%s', $process->isRunning() ? 'yes' : 'no', PHP_EOL);

echo PHP_EOL, '--- asking the server to signal it ---', PHP_EOL;

// signal() sends the request RFC 4254 defines for exactly this. Whether
// anything happens is up to the server, and OpenSSH's sshd does not act on it
// at all - so treat this as a best effort, never as a guarantee.
$process->signal(15);

try {
    $process->join(new TimeoutCancellation(2));

    echo 'The server acted on the signal.', PHP_EOL;
} catch (CancelledException) {
    echo 'The signal was ignored, which is what OpenSSH does.', PHP_EOL;
}

// join() returns false rather than a number when the server closed the channel
// without reporting a status, so === 0 is the safe test for success.
\printf('Exit status: %s%s', \var_export($process->join(), true), PHP_EOL);

echo PHP_EOL, '--- bounding the command where it runs ---', PHP_EOL;

// Since the signal may go nowhere, put the limit on the server side. This is
// the portable answer, it needs nothing from the SSH layer, and the command is
// gone whatever happens to this process or this connection.
$started = \microtime(true);

$guarded = new Process($ssh, 'timeout 2 sleep 30; echo "timeout exited with $?"');
$guarded->start();

$output = \trim(ByteStream\buffer($guarded->getStdout()));
$guarded->join();

\printf('%s after %.1fs%s', $output, \microtime(true) - $started, PHP_EOL);

// The other reliable option is a pseudo terminal: a command started through
// Shell gets one, and closing that channel takes the terminal with it, which
// sends the command SIGHUP. Process does not allocate one, which is why the
// command above survives everything except its own timeout.

echo PHP_EOL, '--- waiting without giving up ---', PHP_EOL;

// Not every timeout should end anything. A long job can be polled: wait
// briefly, report progress, and go back to waiting. The command never notices.
$job = new Process($ssh, 'sleep 4; echo done');
$job->start();

while (true) {
    try {
        \printf('Job finished with status %s%s', \var_export($job->join(new TimeoutCancellation(1)), true), PHP_EOL);

        break;
    } catch (CancelledException) {
        echo 'still working...', PHP_EOL;
    }
}

$ssh->close();
