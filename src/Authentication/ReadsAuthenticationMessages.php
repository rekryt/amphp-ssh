<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Cancellation;
use Amp\Ssh\Message\Debug;
use Amp\Ssh\Message\ExtInfo;
use Amp\Ssh\Message\Ignore;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Message\ServiceAccept;
use Amp\Ssh\Message\ServiceRequest;
use Amp\Ssh\Message\Unimplemented;
use Amp\Ssh\Message\UserAuthBanner;
use Amp\Ssh\Transport\BinaryPacketHandler;

/**
 * The parts of the authentication exchange every method has in common.
 *
 * Two kinds of message can arrive at any point during authentication and say
 * nothing about its outcome. SSH_MSG_EXT_INFO (RFC 8308) is sent right after
 * NEWKEYS, which puts it where SERVICE_ACCEPT is expected. SSH_MSG_USERAUTH_-
 * BANNER (RFC 4252 section 5.4) may be sent at any time before authentication
 * concludes, and OpenSSH sends one whenever Banner is configured.
 *
 * Both have to be consumed where they land rather than mistaken for the reply
 * being waited for. Counting a banner as the reply is not a cosmetic mistake:
 * the checks that follow ask whether the reply was a failure, and a banner is
 * not one - so a server that shows a notice and then rejects the credentials
 * was read as having accepted them.
 *
 * @internal
 */
trait ReadsAuthenticationMessages {
    /** @var string[] */
    private array $serverSignatureAlgorithms = [];

    private ?string $banner = null;

    /**
     * The notice the server displayed, if it displayed one.
     *
     * This is what a server puts in front of a user before they log in, so it
     * is worth being able to show. Read it once connect() has returned, from
     * the Authentication object that was handed to it.
     */
    public function getBanner(): ?string {
        return $this->banner;
    }

    /**
     * Asks for the user authentication service, and checks it was granted.
     *
     * The reply used to be read and thrown away, so a server that refused the
     * service was never noticed and everything after it was addressed to a
     * service that had not been started.
     */
    private function requestUserAuthService(BinaryPacketHandler $handler, ?Cancellation $cancellation): void {
        $request = new ServiceRequest();
        $request->serviceName = 'ssh-userauth';

        $handler->write($request);

        $packet = $this->readMessage($handler, $cancellation);

        if ($packet === null) {
            throw new AuthenticationFailureException(
                'The connection closed while asking the server for the ssh-userauth service'
            );
        }

        if (!$packet instanceof ServiceAccept || $packet->serviceName !== 'ssh-userauth') {
            throw new AuthenticationFailureException('The server did not grant the ssh-userauth service');
        }
    }

    /**
     * Reads the next message that says something about authentication.
     */
    private function readMessage(BinaryPacketHandler $handler, ?Cancellation $cancellation): Message|string|null {
        while (true) {
            $packet = $handler->read($cancellation);

            if ($packet instanceof ExtInfo) {
                $this->serverSignatureAlgorithms = $packet->getServerSignatureAlgorithms();

                continue;
            }

            if ($packet instanceof UserAuthBanner) {
                // More than one is allowed, so they accumulate rather than
                // replace one another.
                $this->banner = ($this->banner ?? '') . $packet->message;

                continue;
            }

            // RFC 4253 sections 11.2 to 11.4 let these arrive at any time, so
            // they are noise here rather than an answer.
            if ($packet instanceof Debug || $packet instanceof Ignore || $packet instanceof Unimplemented) {
                continue;
            }

            return $packet;
        }
    }
}
