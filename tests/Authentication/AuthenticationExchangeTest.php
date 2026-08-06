<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Authentication;

use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\UsernamePassword;
use Amp\Ssh\Message\ServiceAccept;
use Amp\Ssh\Message\UserAuthBanner;
use Amp\Ssh\Message\UserAuthFailure;
use Amp\Ssh\Message\UserAuthSuccess;
use Amp\Ssh\Tests\Channel\FakeHandler;

/**
 * The parts of authentication that are the same whichever method is used.
 *
 * No server needed: the replies are scripted, which is the only practical way
 * to test a server that shows a banner - it takes a line in sshd_config, and
 * the test container does not have one.
 */
class AuthenticationExchangeTest extends AsyncTestCase {
    private function serviceAccepted(): ServiceAccept {
        $accept = new ServiceAccept();
        $accept->serviceName = 'ssh-userauth';

        return $accept;
    }

    private function banner(string $message): UserAuthBanner {
        $banner = new UserAuthBanner();
        $banner->message = $message;
        $banner->languageTag = 'en';

        return $banner;
    }

    private function rejection(): UserAuthFailure {
        $failure = new UserAuthFailure();
        $failure->partialSuccess = false;
        $failure->authThatCanContinue = ['publickey'];

        return $failure;
    }

    /**
     * @param array<int, object> $replies
     */
    private function authenticateAgainst(array $replies, UsernamePassword $authentication): void {
        $handler = new FakeHandler();

        foreach ($replies as $reply) {
            $handler->deliver($reply);
        }

        $authentication->authenticate($handler, 'session-id', null);
    }

    /**
     * A banner is not an answer, and must not be read as one.
     *
     * RFC 4252 section 5.4 lets SSH_MSG_USERAUTH_BANNER arrive at any point
     * before authentication concludes, and OpenSSH sends one whenever Banner is
     * configured. It used to be taken for the reply, and since the check that
     * follows asks only whether the reply was a failure, a banner passed it -
     * so a server that showed a notice and then rejected the password was read
     * as having accepted it.
     */
    public function testABannerBeforeARejectionIsStillARejection() {
        $this->expectException(AuthenticationFailureException::class);

        $this->authenticateAgainst(
            [$this->serviceAccepted(), $this->banner("Authorised users only.\n"), $this->rejection()],
            new UsernamePassword('root', 'the wrong password')
        );
    }

    public function testABannerBeforeAnAcceptanceIsStillAnAcceptance() {
        $authentication = new UsernamePassword('root', 'the right password');

        $this->authenticateAgainst(
            [$this->serviceAccepted(), $this->banner("Welcome.\n"), new UserAuthSuccess()],
            $authentication
        );

        self::assertSame("Welcome.\n", $authentication->getBanner());
    }

    /**
     * More than one banner is allowed, and none at all is the usual case.
     */
    public function testBannersAccumulateAndAreAbsentByDefault() {
        $authentication = new UsernamePassword('root', 'the right password');

        $this->authenticateAgainst(
            [$this->serviceAccepted(), $this->banner('first '), $this->banner('second'), new UserAuthSuccess()],
            $authentication
        );

        self::assertSame('first second', $authentication->getBanner());

        $quiet = new UsernamePassword('root', 'the right password');

        $this->authenticateAgainst([$this->serviceAccepted(), new UserAuthSuccess()], $quiet);

        self::assertNull($quiet->getBanner());
    }

    /**
     * The reply to the service request used to be read and discarded, so a
     * server that refused ssh-userauth was never noticed and everything after
     * it was addressed to a service that had not been started.
     */
    public function testAServiceTheServerDidNotGrantIsReported() {
        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessage('did not grant the ssh-userauth service');

        $this->authenticateAgainst([$this->rejection()], new UsernamePassword('root', 'password'));
    }

    public function testAConnectionLostBeforeTheServiceReplyIsReported() {
        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessage('closed while asking');

        $handler = new FakeHandler();
        $handler->disconnect();

        (new UsernamePassword('root', 'password'))->authenticate($handler, 'session-id', null);
    }
}
