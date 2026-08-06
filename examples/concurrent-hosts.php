<?php declare(strict_types=1);

// Running one command on many hosts at the same time.
//
// This is what an asynchronous SSH client is for. The hosts are contacted
// concurrently, so the run takes about as long as the slowest single host
// instead of the sum of all of them.
//
// Two details matter more than the fan-out itself:
//
//   - concurrent() caps how many connections exist at once. Without a cap, a
//     list of five hundred hosts opens five hundred sockets, and the local
//     file descriptor limit decides the outcome rather than the network.
//   - every failure is caught inside the worker. An exception escaping the
//     closure would abandon the whole pipeline, so a single unreachable host
//     would hide the results of every host that did answer.
//
// Usage:
//   SSH_HOSTS=web1.example.com,web2.example.com:2222 php examples/concurrent-hosts.php 'uptime'

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\Pipeline\Pipeline;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;
use Amp\TimeoutCancellation;

const CONCURRENT_CONNECTIONS = 5;

$command = $argv[1] ?? 'uptime';
$hosts = \array_filter(\array_map('trim', \explode(',', \getenv('SSH_HOSTS') ?: $target)));

/**
 * Connects to one host, runs the command, and always returns a result.
 *
 * Nothing is allowed to throw out of here: the caller wants to know what
 * happened on every host, including the ones that failed.
 */
$runOnHost = static function (string $host) use ($username, $keyPath, $command): array {
    try {
        $ssh = connect(
            $host,
            new PublicKey($username, $keyPath),
            cancellation: new TimeoutCancellation(10)
        );
    } catch (\Throwable $exception) {
        return ['host' => $host, 'ok' => false, 'output' => 'connect: ' . $exception->getMessage()];
    }

    try {
        $process = new Process($ssh, $command);
        $process->start();

        $output = ByteStream\buffer($process->getStdout());
        $errors = ByteStream\buffer($process->getStderr());
        $exitCode = $process->join(new TimeoutCancellation(30));

        return [
            'host' => $host,
            'ok' => $exitCode === 0,
            'output' => \rtrim($exitCode === 0 ? $output : $output . $errors),
        ];
    } catch (\Throwable $exception) {
        return ['host' => $host, 'ok' => false, 'output' => $exception->getMessage()];
    } finally {
        // Each host owns its connection, so each one has to close it.
        $ssh->close();
    }
};

$started = \microtime(true);

$results = Pipeline::fromIterable($hosts)
    ->concurrent(CONCURRENT_CONNECTIONS)
    // Report each host in the order it answered rather than the order it was
    // listed. Drop this line if the output order has to be stable.
    ->unordered()
    ->map($runOnHost)
    ->toArray();

foreach ($results as $result) {
    \printf('%s %s%s', $result['ok'] ? '[ ok ]' : '[fail]', $result['host'], PHP_EOL);

    foreach (\explode("\n", $result['output']) as $line) {
        echo '       ', $line, PHP_EOL;
    }
}

$failed = \count(\array_filter($results, static fn (array $result): bool => !$result['ok']));

\printf(
    '%s%d host(s), %d failed, %.1fs total (roughly the slowest host, not the sum)%s',
    PHP_EOL,
    \count($results),
    $failed,
    \microtime(true) - $started,
    PHP_EOL
);

exit($failed === 0 ? 0 : 1);
