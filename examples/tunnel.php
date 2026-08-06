<?php declare(strict_types=1);

// Reaching something only the server can reach.
//
// createTunnel() asks the server to connect somewhere and hands back the other
// end of that connection. It is `ssh -L` without the local port, and because
// the result satisfies Amp\Socket\Socket, anything that takes a socket can be
// pointed through it without knowing SSH is involved.
//
// The address is resolved and dialled by the server, which is the whole point:
// a database on a private network, an admin port bound to the server's own
// loopback, a host behind its firewall.
//
// One thing it cannot do is TLS. PHP sets that up in the stream layer, on a
// socket resource, and a tunnel is a channel inside the SSH connection rather
// than a socket of its own - isTlsConfigurationAvailable() says so. The hop
// between here and the server is encrypted by SSH regardless; what is missing
// is TLS from here to the far end.

require_once __DIR__ . '/bootstrap.php';

use Amp\Ssh\Authentication\PublicKey;
use Amp\Ssh\Channel\ChannelException;
use function Amp\Ssh\connect;

$ssh = connect($target, new PublicKey($username, $keyPath));

// An ordinary HTTP request, except that the connection is made from the
// server rather than from here.
$tunnel = $ssh->createTunnel('example.com', 80);

\printf('Connected to %s%s', $tunnel->getRemoteAddress()->toString(), PHP_EOL);

$tunnel->write("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");

$response = '';

while (null !== ($chunk = $tunnel->read())) {
    $response .= $chunk;

    // Enough to see the status line; a real client would read to the end.
    if (\strlen($response) > 512) {
        break;
    }
}

echo \strtok($response, "\r\n"), PHP_EOL;
$tunnel->close();

// Something bound to the server's own loopback, which nothing outside the
// server can dial at all.
echo PHP_EOL, 'The server talking to itself:', PHP_EOL;

$tunnel = $ssh->createTunnel('127.0.0.1', 22);

echo '  ', \trim((string) $tunnel->read()), PHP_EOL;
$tunnel->close();

// A connection the server could not make comes back as the channel failing to
// open, carrying the reason the server gave for it.
echo PHP_EOL, 'A port with nothing behind it:', PHP_EOL;

try {
    $ssh->createTunnel('127.0.0.1', 1);

    echo '  opened, which it should not have', PHP_EOL;
} catch (ChannelException $exception) {
    echo '  ', $exception->getMessage(), PHP_EOL;
}

// Tunnels are channels like any other: several at once, alongside commands,
// all on the one connection. Closing one closes only that one.
echo PHP_EOL, 'Two tunnels and a command, on one connection:', PHP_EOL;

$first = $ssh->createTunnel('127.0.0.1', 22);
$second = $ssh->createTunnel('127.0.0.1', 22);

$process = new Amp\Ssh\Process($ssh, 'echo the session is unaffected');
$process->start();

echo '  ', \trim(Amp\ByteStream\buffer($process->getStdout())), PHP_EOL;
$process->join();

$first->close();
$second->close();

$ssh->close();
