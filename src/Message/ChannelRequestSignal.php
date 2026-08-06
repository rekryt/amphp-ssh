<?php declare(strict_types=1);

namespace Amp\Ssh\Message;

use Amp\Ssh\Internal\Signals;
use function Amp\Ssh\Transport\read_string;

/**
 * Asking the server to signal the command running on a channel.
 *
 * @internal
 */
final class ChannelRequestSignal extends ChannelRequest {
    public $signal;

    public $wantReply = false;

    public function encode(): string {
        $signal = \is_int($this->signal) ? Signals::name($this->signal) : $this->signal;

        if ($signal === null) {
            throw new \InvalidArgumentException(\sprintf(
                'Signal %d has no name in RFC 4254; pass one of %s instead.',
                $this->signal,
                \implode(', ', Signals::names())
            ));
        }

        return parent::encode() . \pack(
            'Na*',
            \strlen($signal),
            $signal
        );
    }

    public function getType() {
        return self::TYPE_SIGNAL;
    }

    protected function decodeExtraData($extraPayload) {
        $this->signal = Signals::number(read_string($extraPayload));
    }
}
