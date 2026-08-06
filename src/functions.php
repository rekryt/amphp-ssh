<?php declare(strict_types=1);

namespace Amp\Ssh;

use Amp\Cancellation;
use Amp\Socket\ConnectContext;
use Amp\Socket\Socket;
use Amp\Socket\SocketConnector;
use Amp\Ssh\Authentication\Authentication;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\HostKey\HostKeyVerifier;
use Amp\Ssh\HostKey\KnownHosts;
use Amp\Ssh\Transport\LoggerHandler;
use Amp\Ssh\Transport\MessageHandler;
use Amp\Ssh\Transport\PayloadHandler;
use Amp\Ssh\Transport\ServerIdentificationException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Open an SSH connection and authenticate it.
 *
 * Everything up to the returned resource is all or nothing: if the handshake or
 * the authentication throws, or the cancellation fires, the socket is closed
 * before the exception leaves this function. A half negotiated connection has
 * encryption installed on one side only and can never be recovered, so it must
 * not be observable by the caller.
 *
 * Once the resource has been returned, cancellation no longer applies to it;
 * shutting down is an explicit SshResource::close() call.
 *
 * A connector, when given, replaces the process-wide default from
 * Amp\Socket\socketConnector() for this connection only. Reaching the server
 * through a proxy, or through another SSH tunnel, is a per-connection
 * decision and should not require swapping global state.
 */
function connect(
    string $uri,
    Authentication $authentication,
    ?LoggerInterface $logger = null,
    string $identification = 'SSH-2.0-AmpSSH_0.1',
    ?Cancellation $cancellation = null,
    ?ConnectContext $connectContext = null,
    ?HostKeyVerifier $hostKeyVerifier = null,
    ?SocketConnector $connector = null
): SshResource {
    $logger = $logger ?? new NullLogger();

    // Defaults to checking known_hosts. Skipping the check has to be asked for
    // by name, with AcceptAnyHostKey, so that it is visible in the code that
    // does it rather than being what happens when nobody thought about it.
    $hostKeyVerifier = $hostKeyVerifier ?? new KnownHosts();

    $socket = ($connector ?? \Amp\Socket\socketConnector())->connect($uri, $connectContext, $cancellation);

    try {
        $socket->write($identification . "\r\n");

        $remainder = '';
        $serverIdentification = read_server_identification($socket, $remainder, $cancellation);

        $payloadHandler = new PayloadHandler($socket, $remainder);
        $messageHandler = MessageHandler::create($payloadHandler);
        $loggerHandler = new LoggerHandler($messageHandler, $logger);

        $negotiator = Negotiator::create();
        $cryptedHandler = $negotiator->negotiate($loggerHandler, $serverIdentification, $identification, $cancellation);

        // The signature was checked inside negotiate(); this decides whether
        // the key that signed it belongs to the host we meant to reach.
        [$host, $port] = split_authority($uri);
        $hostKeyVerifier->verify($host, $port, $negotiator->getHostKeyFormat(), $negotiator->getHostKey());

        $authentication->authenticate($cryptedHandler, $negotiator->getSessionId(), $cancellation);

        $dispatcher = new Dispatcher($cryptedHandler);

        // A server may ask for fresh keys at any point; OpenSSH does so by
        // volume and by time. The dispatcher owns reading, so it is the only
        // place that can answer without racing the ordinary packet flow.
        $dispatcher->enableRekey($negotiator, $messageHandler, $serverIdentification, $identification);

        $dispatcher->start();

        return new SshResource($cryptedHandler, $dispatcher);
    } catch (\Throwable $exception) {
        $socket->close();

        throw $exception;
    }
}

/**
 * Splits a connect URI into host and port for host key lookups.
 *
 * Accepts the forms Amp\Socket\connect() does: "host:port", "[v6]:port" and a
 * bare host. Anything without a port is treated as the SSH default, which is
 * also how known_hosts records it.
 *
 * @return array{0: string, 1: int}
 *
 * @internal
 */
function split_authority(string $uri): array {
    $authority = \str_contains($uri, '://') ? \substr($uri, \strpos($uri, '://') + 3) : $uri;

    if (\preg_match('/^\[(?<host>[^\]]+)\](?::(?<port>\d+))?$/', $authority, $matches) === 1) {
        return [$matches['host'], (int) ($matches['port'] ?? 22)];
    }

    $position = \strrpos($authority, ':');

    if ($position === false) {
        return [$authority, 22];
    }

    $host = \substr($authority, 0, $position);
    $port = \substr($authority, $position + 1);

    // A bare IPv6 address has several colons and no port.
    if (\str_contains($host, ':') || !\ctype_digit($port)) {
        return [$authority, 22];
    }

    return [$host, (int) $port];
}

/**
 * Read the server's identification string, skipping any preamble.
 *
 * The server MAY send other lines of data before sending the version
 * string.  Each line SHOULD be terminated by a Carriage Return and Line
 * Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
 * in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
 * MUST be able to process such lines.  Such lines MAY be silently
 * ignored, or MAY be displayed to the client user.
 *
 * Anything read past the identification line is handed back through
 * $remainder: it already belongs to the binary packet protocol.
 *
 * @throws ServerIdentificationException If the peer hangs up first, or sends so
 *                                       much without a line beginning with
 *                                       "SSH-" that it cannot be one.
 *
 * @internal
 */
function read_server_identification(Socket $socket, string &$remainder, ?Cancellation $cancellation): string {
    $buffer = '';

    while (true) {
        $chunk = $socket->read($cancellation);

        if ($chunk === null) {
            throw ServerIdentificationException::connectionClosed();
        }

        $buffer .= $chunk;

        while (($linePos = \strpos($buffer, "\n")) !== false) {
            $line = \substr($buffer, 0, $linePos);
            $buffer = \substr($buffer, $linePos + 1);

            if (\strpos($line, 'SSH-') === 0) {
                $remainder = $buffer;

                // OpenSSH before 7.5 does not always send CR before LF
                return \rtrim($line, "\r");
            }
        }

        // Only unterminated data is held here; complete preamble lines have
        // been consumed above. Without this bound a peer that sends bytes and
        // never a newline grows the buffer for as long as it cares to, which
        // costs it nothing and costs us all the memory we have.
        if (\strlen($buffer) > ServerIdentificationException::MAX_PREAMBLE_BYTES) {
            throw ServerIdentificationException::preambleTooLong();
        }
    }
}
