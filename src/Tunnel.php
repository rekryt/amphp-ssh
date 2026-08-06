<?php declare(strict_types=1);

namespace Amp\Ssh;

use Amp\ByteStream\ClosedException;
use Amp\ByteStream\ReadableStreamIteratorAggregate;
use Amp\Cancellation;
use Amp\DeferredFuture;
use Amp\Socket\InternetAddress;
use Amp\Socket\Socket;
use Amp\Socket\SocketAddress;
use Amp\Socket\SocketException;
use Amp\Socket\TlsInfo;
use Amp\Socket\TlsState;
use Amp\Ssh\Channel\ChannelInputStream;
use Amp\Ssh\Channel\ChannelOutputStream;
use Amp\Ssh\Channel\DirectTcpIp;

/**
 * A connection the SSH server makes on your behalf, shaped like a socket.
 *
 * This is `ssh -L` without the local port: the server connects to the address
 * you name and this object is the other end of it. Because it satisfies
 * Amp\Socket\Socket, anything that takes a socket can be pointed through the
 * tunnel - an HTTP client, a database driver - without knowing SSH is involved.
 *
 * Get one from SshResource::createTunnel(). It stays open until it is closed
 * or the connection carrying it goes away, and closing it closes only that one
 * channel; the SSH connection and any other tunnel on it are unaffected.
 *
 * @implements \IteratorAggregate<int, string>
 */
final class Tunnel implements Socket, \IteratorAggregate {
    use ReadableStreamIteratorAggregate;

    private DirectTcpIp $channel;

    private ChannelInputStream $input;

    private ChannelOutputStream $output;

    private SocketAddress $localAddress;

    private SocketAddress $remoteAddress;

    private DeferredFuture $onClose;

    private bool $closed = false;

    /**
     * Whatever a limited read left over.
     *
     * A channel delivers whole messages, and Socket::read() may be asked for
     * fewer bytes than one of them holds. The remainder waits here rather than
     * being dropped.
     */
    private string $buffer = '';

    /**
     * @internal Use SshResource::createTunnel().
     */
    public function __construct(DirectTcpIp $channel) {
        $this->channel = $channel;
        $this->input = new ChannelInputStream($channel->getDataIterator());
        $this->output = new ChannelOutputStream($channel);
        $this->onClose = new DeferredFuture();

        $this->remoteAddress = self::address($channel->getHost(), $channel->getPort());
        $this->localAddress = self::address($channel->getOriginatorHost(), $channel->getOriginatorPort());
    }

    /**
     * An InternetAddress where the host is a literal address, ours otherwise.
     */
    private static function address(string $host, int $port): SocketAddress {
        $literal = \str_contains($host, ':') ? \sprintf('[%s]:%d', $host, $port) : \sprintf('%s:%d', $host, $port);

        return InternetAddress::tryFromString($literal) ?? new TunnelAddress($host, $port);
    }

    public function read(?Cancellation $cancellation = null, ?int $limit = null): ?string {
        if ($this->buffer === '') {
            $chunk = $this->input->read($cancellation);

            if ($chunk === null) {
                return null;
            }

            $this->buffer = $chunk;
        }

        if ($limit === null || $limit >= \strlen($this->buffer)) {
            $chunk = $this->buffer;
            $this->buffer = '';

            return $chunk;
        }

        $chunk = \substr($this->buffer, 0, $limit);
        $this->buffer = \substr($this->buffer, $limit);

        return $chunk;
    }

    public function isReadable(): bool {
        return $this->buffer !== '' || $this->input->isReadable();
    }

    /**
     * @throws ClosedException If the tunnel has been ended or closed.
     */
    public function write(string $bytes): void {
        $this->output->write($bytes);
    }

    /**
     * Signals that nothing more will be sent, leaving the other direction open.
     */
    public function end(): void {
        $this->output->end();
    }

    public function isWritable(): bool {
        return $this->output->isWritable();
    }

    public function close(): void {
        if ($this->closed) {
            return;
        }

        $this->closed = true;

        $this->input->close();
        $this->output->close();
        $this->channel->close();

        $this->onClose->complete();
    }

    public function isClosed(): bool {
        return $this->closed;
    }

    public function onClose(\Closure $onClose): void {
        $this->onClose->getFuture()->finally($onClose);
    }

    /**
     * Where the server was asked to connect.
     */
    public function getRemoteAddress(): SocketAddress {
        return $this->remoteAddress;
    }

    /**
     * The originating address given to the server when the channel was opened.
     *
     * It is what the server writes in its logs and matches any "from"
     * restriction against; it is not a local socket, because there is no local
     * socket involved.
     */
    public function getLocalAddress(): SocketAddress {
        return $this->localAddress;
    }

    /**
     * TLS cannot be set up on a tunnel.
     *
     * PHP performs TLS in the stream layer, on a socket resource. A tunnel is
     * a channel inside an SSH connection and has no resource of its own, so
     * there is nothing for stream_socket_enable_crypto() to work on. This is
     * why the interface asks first, and the answer here is no.
     *
     * The traffic is still encrypted - by SSH, between here and the server.
     * What is not available is TLS between here and whatever the server
     * connected to, so a tunnel reaches a plaintext service rather than
     * standing in for an HTTPS connection end to end.
     */
    public function isTlsConfigurationAvailable(): bool {
        return false;
    }

    public function setupTls(?Cancellation $cancellation = null): void {
        throw new SocketException('TLS cannot be set up on an SSH tunnel: it has no socket resource to enable it on');
    }

    public function shutdownTls(?Cancellation $cancellation = null): void {
        throw new SocketException('TLS was never set up on this tunnel');
    }

    public function getTlsState(): TlsState {
        return TlsState::Disabled;
    }

    public function getTlsInfo(): ?TlsInfo {
        return null;
    }
}
