<?php declare(strict_types=1);

// Several commands over one connection.
//
// A connection is not a command. Opening one costs a TCP handshake, a key
// exchange and an authentication round trip - easily a good fraction of a
// second on a remote host - while opening a channel on an existing connection
// costs one packet each way.
//
// So connect once and reuse it. The channels are multiplexed over the same
// socket, which also means several commands can run at the same time on one
// connection.
//
// The limit is the server's: sshd caps concurrent channels per connection with
// MaxSessions, which defaults to 10.

require_once __DIR__ . '/bootstrap.php';

use function Amp\async;
use Amp\ByteStream;
use Amp\Future;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;

$ssh = connect($target, new PublicKey($username, $keyPath));

// One command after another, on the connection that is already open.
foreach (['hostname', 'uname -sr', 'df -h /'] as $command) {
    $process = new Process($ssh, $command);
    $process->start();

    $output = ByteStream\buffer($process->getStdout());
    $process->join();

    \printf('$ %s%s%s', $command, PHP_EOL, $output);
}

echo PHP_EOL, '--- and now the same idea concurrently ---', PHP_EOL, PHP_EOL;

// Each async() call gets its own channel. They are interleaved over the one
// socket, so the total time is the slowest command rather than the sum.
$commands = ['sleep 2; echo two', 'sleep 1; echo one', 'sleep 3; echo three'];
$started = \microtime(true);

$futures = [];

foreach ($commands as $command) {
    $futures[] = async(static function () use ($ssh, $command): string {
        $process = new Process($ssh, $command);
        $process->start();

        $output = ByteStream\buffer($process->getStdout());
        $process->join();

        return \rtrim($output);
    });
}

// await() resolves them all and rethrows the first failure. Use awaitAll() if
// one failing command should not discard the results of the others.
$results = Future\await($futures);

foreach ($results as $index => $result) {
    \printf('%-20s -> %s%s', $commands[$index], $result, PHP_EOL);
}

\printf('%s%.1fs for %d commands that sleep 6s in total.%s', PHP_EOL, \microtime(true) - $started, \count($commands), PHP_EOL);

$ssh->close();
