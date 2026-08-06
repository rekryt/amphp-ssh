<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\UsernamePassword;
use function Amp\Ssh\connect;
use Amp\Ssh\SshResource;

class UsernamePasswordTest extends IntegrationTestCase {
    public function testSuccess() {
        $sshResource = connect(
            SshServer::uri(),
            new UsernamePassword(SshServer::user(), SshServer::password()),
            LoggerTest::get()
        );

        self::assertInstanceOf(SshResource::class, $sshResource);

        $sshResource->close();
    }

    public function testFail() {
        $this->expectException(AuthenticationFailureException::class);

        connect(
            SshServer::uri(),
            new UsernamePassword(SshServer::user(), 'bad'),
            LoggerTest::get()
        );
    }
}
