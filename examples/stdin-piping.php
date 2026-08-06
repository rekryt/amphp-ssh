<?php declare(strict_types=1);

// Sending data to a remote command, which is how files get copied, databases
// get restored and archives get unpacked over SSH.
//
// The one rule that catches everyone: call end() when the input is finished.
// It sends EOF on the channel, and until it arrives a command like `cat` or
// `mysql` waits for more input forever - so join() hangs and the cause looks
// like a network problem rather than a missing line of code.

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\ByteStream\ClosedException;
use function Amp\File\openFile;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;

const REMOTE_PATH = '/tmp/amphp-ssh-example.txt';

$ssh = connect($target, new PublicKey($username, $keyPath));

// Write this very file to the server, streaming it rather than reading it into
// memory first. pipe() returns when the source is exhausted; it does not end
// the destination, because a stream may have more than one writer.
$process = new Process($ssh, 'cat > ' . REMOTE_PATH);
$process->start();

$local = openFile(__FILE__, 'r');
$written = ByteStream\pipe($local, $process->getStdin());

$process->getStdin()->end();
$process->join();

\printf('Sent %d bytes to %s.%s', $written, REMOTE_PATH, PHP_EOL);

// Check the server agrees about the size.
$verify = new Process($ssh, 'wc -c < ' . REMOTE_PATH);
$verify->start();

$remoteSize = (int) \trim(ByteStream\buffer($verify->getStdout()));
$verify->join();

\printf(
    'Remote size %d, local size %d: %s%s',
    $remoteSize,
    \filesize(__FILE__),
    $remoteSize === \filesize(__FILE__) ? 'identical' : 'MISMATCH',
    PHP_EOL
);

// Writing in pieces works the same way, and is what you want when the data is
// produced as you go rather than read from a file.
$report = new Process($ssh, 'sort | uniq -c');
$report->start();

$stdin = $report->getStdin();

foreach (['pear', 'apple', 'pear', 'plum', 'apple', 'pear'] as $fruit) {
    $stdin->write($fruit . "\n");
}

$stdin->end();

echo ByteStream\buffer($report->getStdout());
$report->join();

// After end() the stream is finished. In 1.x a write at this point was quietly
// discarded, which hid data being sent to a command that had already exited;
// now it throws.
try {
    $stdin->write("too late\n");
} catch (ClosedException $exception) {
    echo 'Writing after end(): ', $exception->getMessage(), PHP_EOL;
}

$cleanup = new Process($ssh, 'rm -f ' . REMOTE_PATH);
$cleanup->start();
$cleanup->join();

$ssh->close();
