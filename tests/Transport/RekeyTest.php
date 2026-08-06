<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Transport;

use function Amp\async;
use function Amp\delay;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Channel\ChannelException;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Message\ChannelData;
use Amp\Ssh\Message\ChannelOpenConfirmation;
use Amp\Ssh\Message\Debug;
use Amp\Ssh\Message\KeyExchangeInit;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Negotiator;
use Amp\Ssh\Tests\Channel\FakeHandler;
use Amp\Ssh\Transport\MessageHandler;
use Amp\Ssh\Transport\RekeyPacketHandler;
use Amp\TimeoutCancellation;

/**
 * Key re-exchange.
 *
 * A mid-session KEXINIT used to be dropped on the floor: the dispatcher only
 * routed channel messages, so the server waited for a reply that never came
 * and eventually hung up. Under load that reads as a random disconnect.
 */
class RekeyTest extends AsyncTestCase {
    private function serverKex(): KeyExchangeInit {
        $kex = new KeyExchangeInit();
        $kex->cookie = \random_bytes(16);
        $kex->kexAlgorithms = ['curve25519-sha256@libssh.org'];
        $kex->serverHostKeyAlgorithms = ['ssh-ed25519'];
        $kex->encryptionAlgorithmsClientToServer = ['aes256-gcm@openssh.com'];
        $kex->encryptionAlgorithmsServerToClient = ['aes256-gcm@openssh.com'];
        $kex->macAlgorithmsClientToServer = ['hmac-sha2-256'];
        $kex->macAlgorithmsServerToClient = ['hmac-sha2-256'];
        $kex->compressionAlgorithmsClientToServer = ['none'];
        $kex->compressionAlgorithmsServerToClient = ['none'];

        return $kex;
    }

    /**
     * The first move of a rekey: the client has to answer with its own
     * KEXINIT rather than ignore the request.
     */
    public function testServerInitiatedRekeyIsAnswered() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->enableRekey(Negotiator::create(), MessageHandler::create($handler), 'SSH-2.0-Fake', 'SSH-2.0-AmpSSH_0.1');
        $dispatcher->start();

        $handler->deliver($this->serverKex());

        // The exchange cannot finish against a fake peer; hanging up afterwards
        // ends it without leaving the fiber suspended.
        $handler->disconnect();

        delay(0.05);

        $answered = \array_filter(
            $handler->written,
            static fn ($message) => $message instanceof KeyExchangeInit
        );

        self::assertNotEmpty($answered, 'The client must reply to a mid-session KEXINIT');
    }

    /**
     * A connection that was never set up for rekeying must say so instead of
     * quietly ignoring the request and waiting to be disconnected.
     */
    public function testRekeyWithoutSupportFailsLoudly() {
        $handler = new FakeHandler();
        $dispatcher = new Dispatcher($handler);
        $dispatcher->start();

        $confirmation = new ChannelOpenConfirmation();
        $confirmation->recipientChannel = 0;
        $confirmation->senderChannel = 0;
        $confirmation->initialWindowSize = 0x100000;
        $confirmation->maximumPacketSize = 0x8000;

        $session = $dispatcher->createSession();
        $handler->deliver($confirmation);
        $session->open();

        $handler->deliver($this->serverKex());

        $this->expectException(ChannelException::class);

        $session->getRequestIterator()->continue();
    }

    /**
     * Channel traffic must wait for the new keys; transport messages must not.
     */
    public function testGateHoldsChannelTrafficButNotTransportMessages() {
        $handler = new FakeHandler();
        $messages = MessageHandler::create($handler);

        $messages->beginRekey();

        $debug = new Debug();
        $debug->alwaysDisplay = false;
        $debug->message = 'still allowed';
        $debug->languageTag = '';
        $messages->write($debug);

        self::assertCount(1, $handler->written, 'A transport message must go out during a rekey');

        $data = new ChannelData();
        $data->recipientChannel = 0;
        $data->data = 'held back';

        $blocked = async(static fn () => $messages->write($data));

        delay(0.02);

        self::assertFalse($blocked->isComplete(), 'Channel traffic must wait for the rekey');
        self::assertCount(1, $handler->written);

        $messages->endRekey();

        $blocked->await(new TimeoutCancellation(2));

        self::assertCount(2, $handler->written, 'The held write must go out once the rekey is over');
    }

    public function testGateStartsOpen() {
        $handler = new FakeHandler();
        $messages = MessageHandler::create($handler);

        self::assertFalse($messages->isRekeying());

        $data = new ChannelData();
        $data->recipientChannel = 0;
        $data->data = 'no rekey in progress';

        $messages->write($data);

        self::assertCount(1, $handler->written);
    }

    /**
     * Data already in flight when a rekey starts is legal and must reach the
     * dispatcher rather than be mistaken for a malformed key exchange reply.
     */
    public function testPacketsArrivingDuringRekeyAreRoutedOnwards() {
        $handler = new FakeHandler();

        $routed = [];
        $filter = new RekeyPacketHandler($handler, static function (Message $message) use (&$routed): void {
            $routed[] = $message;
        });

        $data = new ChannelData();
        $data->recipientChannel = 0;
        $data->data = 'in flight';
        $handler->deliver($data);

        $handler->deliver($this->serverKex());

        $packet = $filter->read(new TimeoutCancellation(2));

        self::assertInstanceOf(KeyExchangeInit::class, $packet, 'The key exchange packet must be returned');
        self::assertCount(1, $routed, 'The channel packet must have been handed to the dispatcher');
        self::assertInstanceOf(ChannelData::class, $routed[0]);
    }

    public function testFilterPassesThroughEndOfStream() {
        $handler = new FakeHandler();
        $filter = new RekeyPacketHandler($handler, static function (Message $message): void {
        });

        $handler->disconnect();

        self::assertNull($filter->read(new TimeoutCancellation(2)));
    }
}
