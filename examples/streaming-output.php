<?php declare(strict_types=1);

// Reading output as it arrives, instead of collecting all of it first.
//
// ByteStream\buffer() is convenient and wrong as soon as the output is large:
// it holds the whole thing in memory and returns nothing until the command has
// finished. A log tail never finishes at all.
//
// getStdout() is a ReadableStream, so it can be consumed incrementally - by
// chunk with read(), or by line with splitLines().

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;

const INTERESTING_LINES = 10;

$ssh = connect($target, new PublicKey($username, $keyPath));

$process = new Process($ssh, 'find /usr/share -type f 2>/dev/null');
$process->start();

$lines = 0;
$bytes = 0;

// splitLines() yields each line as soon as the data for it has arrived. Memory
// use stays flat no matter how much the command produces.
foreach (ByteStream\splitLines($process->getStdout()) as $line) {
    ++$lines;
    $bytes += \strlen($line) + 1;

    if ($lines <= INTERESTING_LINES) {
        echo $line, PHP_EOL;
    }

    if ($lines === INTERESTING_LINES) {
        echo '...', PHP_EOL;
    }
}

\printf('%s%d lines, %d bytes.%s', PHP_EOL, $lines, $bytes, PHP_EOL);
$process->join();

echo PHP_EOL, '--- when only the first few lines are wanted ---', PHP_EOL;

// Reading can stop whenever you like, but it only releases this side. The
// command carries on running and producing output, because nothing about
// abandoning a stream travels back to the server - kill() would be the obvious
// answer and OpenSSH ignores it, as timeouts.php shows.
//
// So bound the work where it is being done. `head` closes the pipe, the
// producer gets SIGPIPE, and the command is over in a few milliseconds instead
// of scanning the whole filesystem for output nobody will read.
$search = new Process($ssh, 'find / -type f 2>/dev/null | head -5');
$search->start();

foreach (ByteStream\splitLines($search->getStdout()) as $line) {
    echo $line, PHP_EOL;
}

$search->join();

$ssh->close();
