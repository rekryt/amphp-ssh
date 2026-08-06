<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

use Amp\Cancellation;
use Amp\DeferredFuture;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message;

/**
 * @internal
 */
class MessageHandler implements BinaryPacketHandler {
    /** Everything below this number belongs to the transport layer. */
    private const TRANSPORT_LAYER_LIMIT = 50;

    private BinaryPacketHandler $handler;

    private ?DeferredFuture $rekeyGate = null;

    /** @var array<int, class-string<Message\Message>> */
    private array $messageClassRegistry = [];

    public function __construct(BinaryPacketHandler $handler) {
        $this->handler = $handler;
    }

    public function registerMessageClass(string $messageClass): void {
        if (!\is_subclass_of($messageClass, Message\Message::class)) {
            throw new \RuntimeException(\sprintf('%s must be a instance of Message', $messageClass));
        }

        $this->messageClassRegistry[$messageClass::getNumber()] = $messageClass;
    }

    public static function create(...$args) {
        $static = new static(...$args);
        $static->registerMessageClass(Message\Disconnect::class);
        $static->registerMessageClass(Message\Ignore::class);
        $static->registerMessageClass(Message\Unimplemented::class);
        $static->registerMessageClass(Message\Debug::class);
        $static->registerMessageClass(Message\ServiceRequest::class);
        $static->registerMessageClass(Message\ServiceAccept::class);
        $static->registerMessageClass(Message\ExtInfo::class);
        $static->registerMessageClass(Message\KeyExchangeInit::class);
        $static->registerMessageClass(Message\NewKeys::class);
        $static->registerMessageClass(Message\KeyExchangeCurveInit::class);
        $static->registerMessageClass(Message\KeyExchangeCurveReply::class);
        $static->registerMessageClass(Message\UserAuthRequest::class);
        $static->registerMessageClass(Message\UserAuthFailure::class);
        $static->registerMessageClass(Message\UserAuthSuccess::class);
        $static->registerMessageClass(Message\UserAuthBanner::class);
        $static->registerMessageClass(Message\UserAuthPkOk::class);
        $static->registerMessageClass(Message\GlobalRequest::class);
        $static->registerMessageClass(Message\ChannelOpen::class);
        $static->registerMessageClass(Message\ChannelOpenConfirmation::class);
        $static->registerMessageClass(Message\ChannelOpenFailure::class);
        $static->registerMessageClass(Message\ChannelWindowAdjust::class);
        $static->registerMessageClass(Message\ChannelData::class);
        $static->registerMessageClass(Message\ChannelExtendedData::class);
        $static->registerMessageClass(Message\ChannelEof::class);
        $static->registerMessageClass(Message\ChannelClose::class);
        $static->registerMessageClass(Message\ChannelRequest::class);
        $static->registerMessageClass(Message\ChannelSuccess::class);
        $static->registerMessageClass(Message\ChannelFailure::class);

        return $static;
    }

    public function updateDecryption(Decryption $decryption, Mac $decryptMac): void {
        $this->handler->updateDecryption($decryption, $decryptMac);
    }

    public function updateEncryption(Encryption $encryption, Mac $encryptMac): void {
        $this->handler->updateEncryption($encryption, $encryptMac);
    }

    public function read(?Cancellation $cancellation = null): Message\Message|string|null {
        $packet = $this->handler->read($cancellation);

        if ($packet === null) {
            return null;
        }

        if ($packet instanceof Message\Message) {
            return $packet;
        }

        if ($packet === '') {
            throw new TruncatedPacketException('Empty packet payload, expected at least a message number');
        }

        $type = \unpack('C', $packet)[1];

        if (\array_key_exists($type, $this->messageClassRegistry)) {
            $class = $this->messageClassRegistry[$type];
            $packet = $class::decode($packet);
        }

        return $packet;
    }

    /**
     * Holds back application traffic for the duration of a key re-exchange.
     *
     * RFC 4253 section 7.1: once KEXINIT has been sent, nothing but transport
     * layer messages may follow until NEWKEYS. A channel write slipping
     * through would either be encrypted under a key the peer has already
     * retired or arrive where the peer is not expecting it.
     */
    public function beginRekey(): void {
        $this->rekeyGate ??= new DeferredFuture();
    }

    public function endRekey(): void {
        $gate = $this->rekeyGate;
        $this->rekeyGate = null;

        $gate?->complete();
    }

    public function isRekeying(): bool {
        return $this->rekeyGate !== null;
    }

    public function write(Message\Message|string $message): void {
        if ($message instanceof Message\Message) {
            $this->awaitRekey($message::getNumber());

            $message = $message->encode();
        }

        $this->handler->write($message);
    }

    /**
     * Transport and key exchange messages (1-49) must keep flowing during a
     * rekey; user auth and channel traffic waits for it to finish.
     */
    private function awaitRekey(int $number): void {
        if ($number < self::TRANSPORT_LAYER_LIMIT) {
            return;
        }

        while ($this->rekeyGate !== null) {
            $this->rekeyGate->getFuture()->await();
        }
    }

    public function close(): void {
        $this->handler->close();
    }
}
