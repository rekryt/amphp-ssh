<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Channel;

use Amp\Ssh\Channel\ChannelException;
use Amp\Ssh\Channel\Session;
use Amp\Ssh\Tests\IntegrationTestCase;
use Amp\Ssh\Tests\NetworkHelper;

/**
 * The same fail-versus-complete invariant as DispatcherLifecycleTest, but
 * against a real server, so the two cannot silently drift apart.
 */
class SessionTest extends IntegrationTestCase {
    public function testRequestEmitterFailedAfterDisconnect() {
        $connection = $this->getSsh();

        /** @var Session $session */
        $session = $connection->createSession();
        $session->open();

        NetworkHelper::disconnect($connection);

        $this->expectException(ChannelException::class);

        $session->getRequestIterator()->continue();
    }

    public function testDataEmitterClosedAfterDisconnect() {
        $connection = $this->getSsh();

        /** @var Session $session */
        $session = $connection->createSession();
        $session->open();

        NetworkHelper::disconnect($connection);

        self::assertFalse($session->getDataIterator()->continue());
        self::assertFalse($session->getDataExtendedIterator()->continue());
    }

    public function testSessionClosedAfterConnectionClose() {
        $connection = $this->getSsh();

        $session = $connection->createSession();
        $session->open();

        $connection->close();

        self::assertFalse($session->getRequestIterator()->continue());
    }
}
