<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Cancellation;
use Amp\Ssh\Message\UserAuthPkOk;
use Amp\Ssh\Message\UserAuthRequest;
use Amp\Ssh\Message\UserAuthRequestAskPublicKey;
use Amp\Ssh\Message\UserAuthRequestSignedPublicKey;
use Amp\Ssh\Message\UserAuthSuccess;
use Amp\Ssh\Transport\BinaryPacketHandler;

/**
 * Authenticates with the keys an SSH agent is holding.
 *
 * This is the way to use keys this library cannot read itself: those on a
 * hardware security key, where the private half never leaves the token, and
 * encrypted key files, where the agent already knows the passphrase.
 *
 * Each identity is offered in turn, exactly as OpenSSH does, and only the one
 * the server accepts is actually signed - so a security key is not touched
 * until it is the one being used.
 */
final class AgentAuthentication implements Authentication {
    use ReadsAuthenticationMessages;

    private string $username;

    private ?Agent $agent;

    private ?string $address;

    private ?string $comment;

    /**
     * @param string|null $comment Offer only the identity with this comment,
     *                             which is usually the key's file name.
     * @param string|null $address Where the agent listens; defaults to
     *                             SSH_AUTH_SOCK.
     */
    public function __construct(
        string $username,
        ?string $comment = null,
        ?string $address = null,
        ?Agent $agent = null
    ) {
        $this->username = $username;
        $this->comment = $comment;
        $this->address = $address;
        $this->agent = $agent;
    }

    public function authenticate(
        BinaryPacketHandler $handler,
        string $sessionId,
        ?Cancellation $cancellation = null
    ): void {
        $agent = $this->agent ?? Agent::connect($this->address);
        $identities = $agent->getIdentities();

        if ($identities === []) {
            throw new AuthenticationFailureException(
                'The SSH agent is not holding any keys. Add one with `ssh-add`.'
            );
        }

        $this->requestUserAuthService($handler, $cancellation);

        $offered = [];

        foreach ($identities as $identity) {
            if ($this->comment !== null && $identity['comment'] !== $this->comment) {
                continue;
            }

            $key = new AgentKey($agent, $identity['blob'], $identity['comment']);
            $offered[] = \sprintf('%s (%s)', $identity['comment'], $key->getType());

            if ($this->tryKey($handler, $key, $sessionId, $cancellation)) {
                return;
            }
        }

        if ($offered === []) {
            throw new AuthenticationFailureException(\sprintf(
                'The agent holds no key with the comment %s.',
                $this->comment
            ));
        }

        throw new AuthenticationFailureException(\sprintf(
            'The server accepted none of the keys the agent offered: %s.',
            \implode(', ', $offered)
        ));
    }

    /**
     * Offers one key, and signs with it only if the server says it would be
     * accepted.
     */
    private function tryKey(
        BinaryPacketHandler $handler,
        AgentKey $key,
        string $sessionId,
        ?Cancellation $cancellation
    ): bool {
        $algorithm = $key->getSignatureAlgorithm($this->serverSignatureAlgorithms);
        $publicKey = $key->getPublicKeyBlob();

        $request = new UserAuthRequestAskPublicKey();
        $request->username = $this->username;
        $request->authType = UserAuthRequest::TYPE_PUBLIC_KEY;
        $request->keyAlgorithm = $algorithm;
        $request->keyBlob = $publicKey;

        $handler->write($request);

        if (!$this->readMessage($handler, $cancellation) instanceof UserAuthPkOk) {
            return false;
        }

        $signatureRequest = new UserAuthRequestSignedPublicKey();
        $signatureRequest->username = $this->username;
        $signatureRequest->authType = UserAuthRequest::TYPE_PUBLIC_KEY;
        $signatureRequest->keyAlgorithm = $algorithm;
        $signatureRequest->keyBlob = $publicKey;

        $signatureRaw = \pack(
            'Na*a*',
            \strlen($sessionId),
            $sessionId,
            $signatureRequest->encode()
        );

        $signature = $key->sign($signatureRaw, $algorithm);
        $format = $key->getSignatureFormat($algorithm);

        $signatureRequest->signature = \pack(
            'Na*Na*',
            \strlen($format),
            $format,
            \strlen($signature),
            $signature
        );

        $handler->write($signatureRequest);
        $packet = $this->readMessage($handler, $cancellation);

        if ($packet === null) {
            throw new AuthenticationFailureException('Connection closed during authentication');
        }

        // Only an explicit success moves on to the next key; anything else,
        // including whatever a server invents, counts as this key not working.
        return $packet instanceof UserAuthSuccess;
    }
}
