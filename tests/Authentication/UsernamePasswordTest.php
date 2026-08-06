<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\UsernamePassword;
use Amp\Ssh\SshResource;

class UsernamePasswordTest extends IntegrationTestCase {
    public function testSuccess() {
        $sshResource = SshServer::connectWith(
            new UsernamePassword(SshServer::user(), SshServer::password())
        );

        self::assertInstanceOf(SshResource::class, $sshResource);

        $sshResource->close();
    }

    public function testFail() {
        $this->expectException(AuthenticationFailureException::class);

        SshServer::connectWith(new UsernamePassword(SshServer::user(), 'bad'));
    }
}
