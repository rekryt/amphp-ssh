<?php declare(strict_types=1);

// The smallest shell that works. See pty-shell.php for terminal size, TERM,
// raw mode and resize handling.

require_once __DIR__ . '/bootstrap.php';

use function Amp\async;
use Amp\ByteStream;
use Amp\CancelledException;
use Amp\Future;
use Amp\TimeoutCancellation;

$authentication = new \Amp\Ssh\Authentication\PublicKey($username, $keyPath);
$sshResource = \Amp\Ssh\connect($target, $authentication);

$shell = new \Amp\Ssh\Shell($sshResource);
$shell->start();

$piping = [
    async(fn () => ByteStream\pipe($shell->getStdout(), ByteStream\getStdout())),
    async(fn () => ByteStream\pipe($shell->getStderr(), ByteStream\getStderr())),
];

$stdin = ByteStream\getStdin();

async(function () use ($shell, $stdin): void {
    $shell->join();
    $stdin->close();
});

while ($shell->isRunning()) {
    $read = $stdin->read();

    if ($read === null) {
        break;
    }

    // The shell may have exited while that read was pending. Writing to a
    // stream that has already ended now throws instead of being swallowed.
    if (!$shell->getStdin()->isWritable()) {
        break;
    }

    $shell->getStdin()->write($read);
}

// Let the last of the output through before the connection goes away, but do
// not wait on a shell that is still producing it.
try {
    Future\await($piping, new TimeoutCancellation(2));
} catch (CancelledException) {
}

$sshResource->close();
