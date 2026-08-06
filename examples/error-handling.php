<?php declare(strict_types=1);

// What can go wrong, and which exception says so.
//
// The failures arrive in the order the protocol reaches them, and each one
// means something different about what to do next:
//
//   ConnectException                 the host never answered - DNS, firewall, wrong port
//   ServerIdentificationException    something answered, but it does not speak SSH
//   HostKeyVerificationException     it speaks SSH, but it is not the host you trust
//   AuthenticationFailureException   it is the right host and it refused your credentials
//   ChannelException                 the connection was working and then was lost
//   CancelledException               you gave up waiting; see timeouts.php
//
// And the one that is not an exception at all: a command exiting non-zero.
// "the command failed" and "SSH failed" need different handling, so they are
// reported differently.

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\CancelledException;
use Amp\Socket\ConnectException;
use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\PublicKey;
use Amp\Ssh\Channel\ChannelException;
use function Amp\Ssh\connect;
use Amp\Ssh\HostKey\HostKeyVerificationException;
use Amp\Ssh\HostKey\HostKeyVerifier;
use Amp\Ssh\Process;
use Amp\Ssh\Transport\ServerIdentificationException;

/**
 * Runs one scenario and reports which of the failures above came out of it.
 */
function attempt(string $label, \Closure $scenario): void {
    \printf('%s%s%s', PHP_EOL, $label, PHP_EOL);

    try {
        $scenario();

        echo '  -> no error', PHP_EOL;
    } catch (ConnectException $exception) {
        echo '  -> unreachable: ', $exception->getMessage(), PHP_EOL;
    } catch (ServerIdentificationException $exception) {
        // Worth separating from the rest: it usually means the port is right
        // for something else, or a firewall answered on sshd's behalf.
        echo '  -> not an SSH server: ', $exception->getMessage(), PHP_EOL;
    } catch (HostKeyVerificationException $exception) {
        // Never retry past this one. Either the host was rebuilt and the
        // recorded key needs replacing, or something is sitting in the middle.
        echo '  -> untrusted host: ', $exception->getMessage(), PHP_EOL;
    } catch (AuthenticationFailureException $exception) {
        // The server does not say which part it disliked, so neither can we.
        echo '  -> rejected: ', $exception->getMessage(), PHP_EOL;
    } catch (ChannelException $exception) {
        // The connection died while the command was running. Whether the
        // command completed on the far side is unknown, which matters for
        // anything that is not safe to run twice.
        echo '  -> connection lost: ', $exception->getMessage(), PHP_EOL;
    } catch (CancelledException) {
        echo '  -> timed out', PHP_EOL;
    } catch (\Throwable $exception) {
        \printf('  -> %s: %s%s', $exception::class, $exception->getMessage(), PHP_EOL);
    }
}

// This one takes a few seconds rather than failing at once: a connection is
// retried before it is given up on, even when the first refusal was immediate.
attempt('Nothing is listening there', static function () use ($username, $keyPath): void {
    connect('127.0.0.1:1', new PublicKey($username, $keyPath))->close();
});

// A peer that accepts the connection and then says nothing is the case worth
// planning for, because there is no timeout of its own: connect() waits for
// the identification line as long as the peer keeps the socket open. Bound it,
// or a filtered port answers by hanging your process instead of failing it.
//
//     connect($uri, $auth, cancellation: new TimeoutCancellation(10));
//     connect($uri, $auth, connectContext: (new ConnectContext())->withConnectTimeout(5));
//
// If it hangs up, or talks without ever sending a line beginning with "SSH-",
// that is the ServerIdentificationException above. It is not run here because
// producing one reliably means a peer that behaves that way on purpose.

attempt('The host key is not the expected one', static function () use ($target, $username, $keyPath): void {
    $verifier = new class implements HostKeyVerifier {
        public function verify(string $host, int $port, string $format, string $key): void {
            throw new HostKeyVerificationException('this key was never trusted');
        }
    };

    connect($target, new PublicKey($username, $keyPath), hostKeyVerifier: $verifier)->close();
});

attempt('The user does not exist', static function () use ($target, $keyPath): void {
    connect($target, new PublicKey('nobody-by-this-name', $keyPath))->close();
});

attempt('The private key file is missing', static function () use ($target, $username): void {
    connect($target, new PublicKey($username, '/nonexistent/id_rsa'))->close();
});

// A command that fails is an ordinary result, not an error. Only the exit
// status distinguishes it, and stderr usually explains it.
echo PHP_EOL, 'A command that exits non-zero', PHP_EOL;

$ssh = connect($target, new PublicKey($username, $keyPath));

$process = new Process($ssh, 'ls /definitely-not-here');
$process->start();

$errors = ByteStream\buffer($process->getStderr());
$exitCode = $process->join();

\printf('  -> exit status %s, stderr: %s%s', \var_export($exitCode, true), \trim($errors), PHP_EOL);

// join() also answers false, rather than a number, when the server closed the
// channel without reporting a status - a command killed by a signal, usually.
// Comparing with === 0 handles both; treating the result as an int does not.
echo '  -> succeeded? ', $exitCode === 0 ? 'yes' : 'no', PHP_EOL;

$ssh->close();
