<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Negotiator;

use Amp\Ssh\Authentication\UsernamePassword;
use Amp\Ssh\Channel\Dispatcher;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\KeyExchange\KeyExchange;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Negotiator;
use function Amp\Ssh\read_server_identification;
use Amp\Ssh\SshResource;
use Amp\Ssh\Tests\IntegrationTestCase;
use Amp\Ssh\Tests\LoggerTest;
use Amp\Ssh\Tests\SshServer;
use Amp\Ssh\Transport\LoggerHandler;
use Amp\Ssh\Transport\MessageHandler;
use Amp\Ssh\Transport\PayloadHandler;
use Amp\TimeoutCancellation;

/**
 * Exercises one algorithm at a time against a real server.
 *
 * Amp\Ssh\connect() always offers the full set, so the only way to prove a
 * single cipher, MAC or key exchange actually interoperates is to build the
 * handler stack by hand around a Negotiator that offers just that one.
 */
class NegotiatorTest extends IntegrationTestCase {
    protected function connectWith(Negotiator $negotiator): SshResource {
        // SshServer::uri(), never a literal address. This used to dial
        // 127.0.0.1:2222 whatever SSH_LOCAL_HOST said, so pointing the suite at
        // a server somewhere else still sent that server's user name and
        // password to whatever happened to be listening on the local port.
        $uri = SshServer::uri();
        $authentication = new UsernamePassword(SshServer::user(), SshServer::password());
        $identification = 'SSH-2.0-AmpSSH_0.1';
        $logger = LoggerTest::get();

        $socket = \Amp\Socket\connect($uri);

        try {
            $socket->write($identification . "\r\n");

            $remainder = '';
            $serverIdentification = read_server_identification($socket, $remainder, null);

            $payloadHandler = new PayloadHandler($socket, $remainder);
            $messageHandler = MessageHandler::create($payloadHandler);
            $loggerHandler = new LoggerHandler($messageHandler, $logger);

            $cryptedHandler = $negotiator->negotiate($loggerHandler, $serverIdentification, $identification);

            $authentication->authenticate(
                $cryptedHandler,
                $negotiator->getSessionId(),
                // Generous on purpose: this bounds a hung test, and one second
                // was a local-container assumption that a server a few network
                // hops away misses on latency alone.
                new TimeoutCancellation(10)
            );

            $dispatcher = new Dispatcher($cryptedHandler);
            $dispatcher->start();

            return new SshResource($cryptedHandler, $dispatcher);
        } catch (\Throwable $exception) {
            $socket->close();

            // The algorithm under test is one this server does not offer, which
            // is a fact about the server rather than a defect: current OpenSSH
            // has disabled the CBC ciphers and group14-sha1, and
            // docker/legacy.Dockerfile exists to provide a server that still
            // has them. Skipping rather than failing keeps the suite meaningful
            // against whatever sshd it is pointed at - it proves the algorithms
            // that server actually supports, and says plainly which ones it
            // could not be asked about.
            if ($exception instanceof \RuntimeException
                && \str_starts_with($exception->getMessage(), 'No common ')) {
                self::markTestSkipped($exception->getMessage());
            }

            throw $exception;
        }
    }

    /**
     * @dataProvider keyExchanges
     */
    public function testKeyExchange(KeyExchange $keyExchange) {
        $negotiator = new NegotiatorBuilder();
        $negotiator->addKeyExchange($keyExchange);
        $negotiator->addEncryptions();
        $negotiator->addDecryptions();
        $negotiator->addMacs();

        $sshResource = $this->connectWith($negotiator->get());
        self::assertInstanceOf(SshResource::class, $sshResource);
        $sshResource->close();
    }

    /**
     * @dataProvider encryptions
     */
    public function testEncryption(Encryption $encryption) {
        $negotiator = new NegotiatorBuilder();
        $negotiator->addKeyExchanges();
        $negotiator->addEncryption($encryption);
        $negotiator->addDecryptions();
        $negotiator->addMacs();

        $sshResource = $this->connectWith($negotiator->get());
        self::assertInstanceOf(SshResource::class, $sshResource);
        $sshResource->close();
    }

    /**
     * @dataProvider decryptions
     */
    public function testDecryption(Decryption $decryption) {
        $negotiator = new NegotiatorBuilder();
        $negotiator->addKeyExchanges();
        $negotiator->addDecryption($decryption);
        $negotiator->addEncryptions();
        $negotiator->addMacs();

        $sshResource = $this->connectWith($negotiator->get());
        self::assertInstanceOf(SshResource::class, $sshResource);
        $sshResource->close();
    }

    /**
     * @dataProvider macs
     */
    public function testMacs(Mac $mac) {
        $negotiator = new NegotiatorBuilder();
        $negotiator->addKeyExchanges();
        $negotiator->addEncryptions();
        $negotiator->addDecryptions();
        $negotiator->addMac($mac);

        $sshResource = $this->connectWith($negotiator->get());
        self::assertInstanceOf(SshResource::class, $sshResource);
        $sshResource->close();
    }

    public function provider(iterable $items): array {
        $result = [];

        foreach ($items as $item) {
            $result[] = [$item];
        }

        return $result;
    }

    public function keyExchanges(): array {
        return $this->provider(Negotiator::supportedKeyExchanges());
    }

    public function encryptions(): array {
        return $this->provider(Negotiator::supportedEncryptions());
    }

    public function decryptions(): array {
        return $this->provider(Negotiator::supportedDecryptions());
    }

    public function macs(): array {
        return $this->provider(Negotiator::supportedMacs());
    }
}
