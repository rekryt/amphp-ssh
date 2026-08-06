<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Cancellation;
use Amp\Ssh\Message\UserAuthFailure;
use Amp\Ssh\Message\UserAuthRequestPassword;
use Amp\Ssh\Transport\BinaryPacketHandler;

final class UsernamePassword implements Authentication {
    use ReadsAuthenticationMessages;

    private string $username;

    private string $password;

    public function __construct(string $username, string $password) {
        $this->username = $username;
        $this->password = $password;
    }

    public function authenticate(
        BinaryPacketHandler $handler,
        string $sessionId,
        ?Cancellation $cancellation = null
    ): void {
        $this->requestUserAuthService($handler, $cancellation);

        $userAuthRequest = new UserAuthRequestPassword();
        $userAuthRequest->authType = UserAuthRequestPassword::TYPE_PASSWORD;
        $userAuthRequest->username = $this->username;
        $userAuthRequest->password = $this->password;

        $handler->write($userAuthRequest);
        $packet = $this->readMessage($handler, $cancellation);

        if ($packet instanceof UserAuthFailure) {
            throw new AuthenticationFailureException('Authentication failure');
        }

        if ($packet === null) {
            throw new AuthenticationFailureException('Connection closed during authentication');
        }
    }
}
