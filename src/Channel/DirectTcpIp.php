<?php declare(strict_types=1);

namespace Amp\Ssh\Channel;

use Amp\Pipeline\ConcurrentIterator;
use Amp\Ssh\Message\ChannelOpen;
use Amp\Ssh\Transport\BinaryPacketWriter;

/**
 * A channel the server opens to somewhere else on our behalf.
 *
 * This is what an SSH tunnel is made of, and what `ssh -L` uses: the server
 * connects to the address given here and everything written to the channel
 * comes out of that connection. The name is the server's point of view -
 * "direct" because we asked for it, as opposed to forwarded-tcpip, where the
 * server opens the channel towards us.
 *
 * @internal
 */
final class DirectTcpIp extends Channel {
    private string $host;

    private int $port;

    private string $originatorHost;

    private int $originatorPort;

    public function __construct(
        BinaryPacketWriter $writer,
        ConcurrentIterator $channelMessage,
        int $channelId,
        string $host,
        int $port,
        string $originatorHost,
        int $originatorPort
    ) {
        parent::__construct($writer, $channelMessage, $channelId);

        $this->host = $host;
        $this->port = $port;
        $this->originatorHost = $originatorHost;
        $this->originatorPort = $originatorPort;
    }

    public function getHost(): string {
        return $this->host;
    }

    public function getPort(): int {
        return $this->port;
    }

    public function getOriginatorHost(): string {
        return $this->originatorHost;
    }

    public function getOriginatorPort(): int {
        return $this->originatorPort;
    }

    protected function getType(): string {
        return ChannelOpen::TYPE_DIRECT_TCPIP;
    }

    /**
     * RFC 4254 section 7.2: where to connect, and where from.
     *
     * The originator is what the server writes in its logs and what any
     * "from" restriction in its configuration is matched against. It is not
     * verified, and a server is free to ignore it.
     */
    protected function getOpenExtraData(): string {
        return \pack(
            'Na*N',
            \strlen($this->host),
            $this->host,
            $this->port
        ) . \pack(
            'Na*N',
            \strlen($this->originatorHost),
            $this->originatorHost,
            $this->originatorPort
        );
    }
}
