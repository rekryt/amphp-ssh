<?php declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use function Amp\async;
use Amp\ByteStream;
use Amp\Future;

// Any PSR-3 logger receives every packet that goes in or out, which is the
// first thing to reach for when a handshake fails.
$logger = new \Monolog\Logger('ampssh', [
    new \Monolog\Handler\StreamHandler(STDOUT),
]);

$authentication = new \Amp\Ssh\Authentication\PublicKey($username, $keyPath);
$sshResource = \Amp\Ssh\connect($target, $authentication, $logger);

$process = new \Amp\Ssh\Process($sshResource, 'ls -la');

$process->start();

$piping = [
    async(fn () => ByteStream\pipe($process->getStdout(), ByteStream\getStdout())),
    async(fn () => ByteStream\pipe($process->getStderr(), ByteStream\getStderr())),
];

$exitCode = $process->join();

// Drain both streams before tearing the connection down, otherwise output
// still sitting in the channel buffers is lost.
Future\await($piping);

$sshResource->close();

exit(\is_int($exitCode) ? $exitCode : 0);
