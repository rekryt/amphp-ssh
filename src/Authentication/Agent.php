<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\ByteStream\ReadableStream;
use Amp\ByteStream\WritableStream;
use Amp\Socket;
use function Amp\Ssh\Transport\read_string;
use function Amp\Ssh\Transport\read_uint32;

/**
 * A client for the SSH agent protocol (draft-miller-ssh-agent).
 *
 * The agent holds the keys and does the signing, which is the only way to use
 * two kinds of key this library cannot handle itself: those on a hardware
 * security key, whose private half never leaves the token, and encrypted key
 * files, which need a passphrase this client cannot ask for.
 *
 * @internal
 */
final class Agent {
    private const REQUEST_IDENTITIES = 11;

    private const IDENTITIES_ANSWER = 12;

    private const SIGN_REQUEST = 13;

    private const SIGN_RESPONSE = 14;

    private const FAILURE = 5;

    public const FLAG_RSA_SHA2_256 = 2;

    public const FLAG_RSA_SHA2_512 = 4;

    private ReadableStream $input;

    private WritableStream $output;

    private string $buffer = '';

    public function __construct(ReadableStream $input, WritableStream $output) {
        $this->input = $input;
        $this->output = $output;
    }

    /**
     * Connects to the agent the environment points at.
     *
     * @throws AuthenticationFailureException
     */
    public static function connect(?string $address = null): self {
        $address ??= \getenv('SSH_AUTH_SOCK') ?: '';

        if ($address === '') {
            throw new AuthenticationFailureException(
                'No SSH agent to talk to: SSH_AUTH_SOCK is not set. Start one with `eval $(ssh-agent)` and '
                    . 'add your key with `ssh-add`.'
            );
        }

        try {
            $socket = Socket\connect(\str_contains($address, '://') ? $address : 'unix://' . $address);
        } catch (\Throwable $exception) {
            throw new AuthenticationFailureException(
                'Could not reach the SSH agent at ' . $address . ': ' . $exception->getMessage(),
                0,
                $exception
            );
        }

        return new self($socket, $socket);
    }

    /**
     * @return array<int, array{blob: string, comment: string}> The keys the
     *                                                          agent is holding.
     */
    public function getIdentities(): array {
        $response = $this->request(\chr(self::REQUEST_IDENTITIES));

        $type = \ord($response[0]);
        $payload = \substr($response, 1);

        if ($type !== self::IDENTITIES_ANSWER) {
            throw new AuthenticationFailureException('The agent refused to list its identities.');
        }

        $count = read_uint32($payload);
        $identities = [];

        for ($i = 0; $i < $count; ++$i) {
            $identities[] = [
                'blob' => read_string($payload),
                'comment' => read_string($payload),
            ];
        }

        return $identities;
    }

    /**
     * Asks the agent to sign, which is where a hardware token would light up.
     *
     * @return string The complete signature blob, format name included.
     */
    public function sign(string $keyBlob, string $data, int $flags = 0): string {
        $request = \chr(self::SIGN_REQUEST)
            . \pack('Na*', \strlen($keyBlob), $keyBlob)
            . \pack('Na*', \strlen($data), $data)
            . \pack('N', $flags);

        $response = $this->request($request);
        $type = \ord($response[0]);
        $payload = \substr($response, 1);

        if ($type === self::FAILURE) {
            throw new AuthenticationFailureException(
                'The agent refused to sign. If this is a security key, it may have been unplugged or the '
                    . 'touch confirmation may have timed out.'
            );
        }

        if ($type !== self::SIGN_RESPONSE) {
            throw new AuthenticationFailureException('Unexpected reply ' . $type . ' from the SSH agent.');
        }

        return read_string($payload);
    }

    /**
     * Every message is a uint32 length followed by that many bytes.
     */
    private function request(string $message): string {
        $this->output->write(\pack('Na*', \strlen($message), $message));

        $length = \unpack('N', $this->readExactly(4))[1];

        if ($length === 0 || $length > 0x100000) {
            throw new AuthenticationFailureException('The SSH agent sent a reply of implausible length.');
        }

        return $this->readExactly($length);
    }

    /**
     * Reads exactly as many bytes as asked for.
     *
     * The surplus is kept: a socket read is free to return the length prefix
     * and the body of a reply in one go, and throwing that away would lose the
     * start of the message.
     */
    private function readExactly(int $length): string {
        while (\strlen($this->buffer) < $length) {
            $chunk = $this->input->read();

            if ($chunk === null) {
                throw new AuthenticationFailureException('The SSH agent closed the connection.');
            }

            $this->buffer .= $chunk;
        }

        $bytes = \substr($this->buffer, 0, $length);
        $this->buffer = \substr($this->buffer, $length);

        return $bytes;
    }
}
