<?php declare(strict_types=1);

namespace Amp\Ssh\Message;

use Amp\Ssh\Internal\Signals;
use function Amp\Ssh\Transport\read_boolean;
use function Amp\Ssh\Transport\read_string;

/**
 * A server reporting that a command died from a signal rather than exiting.
 *
 * @internal
 */
final class ChannelRequestExitSignal extends ChannelRequest {
    /** Local signal number, or null for a name this platform does not know. */
    public $signal;

    /** The name as it travelled, which is what the RFC actually defines. */
    public string $signalName = '';

    public $coreDumped = false;

    public $errorMessage = '';

    public $languageTag = '';

    public function encode(): string {
        $signal = \is_int($this->signal) ? Signals::name($this->signal) : $this->signal;
        $signal = (string) ($signal ?? $this->signalName);

        // Four fields follow the request header, and the format has to name
        // every one of them: 'Na*C' silently dropped the error message and the
        // language tag, because pack() ignores arguments the format runs out
        // of room for.
        return parent::encode() . \pack(
            'Na*CNa*Na*',
            \strlen($signal),
            $signal,
            (int) $this->coreDumped,
            \strlen((string) $this->errorMessage),
            (string) $this->errorMessage,
            \strlen((string) $this->languageTag),
            (string) $this->languageTag
        );
    }

    public function getType() {
        return self::TYPE_EXIT_SIGNAL;
    }

    protected function decodeExtraData($extraPayload) {
        $this->signalName = read_string($extraPayload);
        $this->signal = Signals::number($this->signalName);
        $this->coreDumped = read_boolean($extraPayload);
        $this->errorMessage = read_string($extraPayload);
        $this->languageTag = read_string($extraPayload);
    }
}
