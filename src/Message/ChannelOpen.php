<?php declare(strict_types=1);

namespace Amp\Ssh\Message;

/**
 * @internal
 */
final class ChannelOpen implements Message {
    const TYPE_SESSION = 'session';
    const TYPE_X11 = 'x11';
    const TYPE_FORWARDED_TCPIP = 'forwarded-tcpip';
    const TYPE_DIRECT_TCPIP = 'direct-tcpip';

    public $channelType;

    public $senderChannel;

    public $initialWindowSize = 0x7FFFFFFF;

    public $maximumPacketSize = 0x4000;

    /**
     * Whatever the channel type adds after the header, already encoded.
     *
     * RFC 4254 gives each type its own tail: a session has none, while
     * direct-tcpip carries the address to connect to and the address it is
     * being connected from.
     */
    public string $extraData = '';

    public function encode(): string {
        return \pack(
            'CNa*N3',
            self::getNumber(),
            \strlen($this->channelType),
            $this->channelType,
            $this->senderChannel,
            $this->initialWindowSize,
            $this->maximumPacketSize
        ) . $this->extraData;
    }

    public static function decode(string $payload) {
        return new static();
    }

    public static function getNumber(): int {
        return self::SSH_MSG_CHANNEL_OPEN;
    }
}
