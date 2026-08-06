<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Cancellation;
use function Amp\File\exists;
use function Amp\File\read;
use Amp\Ssh\Message\UserAuthFailure;
use Amp\Ssh\Message\UserAuthPkOk;
use Amp\Ssh\Message\UserAuthRequest;
use Amp\Ssh\Message\UserAuthRequestAskPublicKey;
use Amp\Ssh\Message\UserAuthRequestSignedPublicKey;
use Amp\Ssh\Transport\BinaryPacketHandler;

final class PublicKey implements Authentication {
    use ReadsAuthenticationMessages;

    private string $privateKeyPath;

    private string $username;

    private string $passphrase;

    private ?string $certificatePath;

    /**
     * @param string|null $certificatePath A user certificate to present with
     *                                     the key. Defaults to the OpenSSH
     *                                     convention of "<key>-cert.pub" beside
     *                                     the private key, when that exists.
     */
    public function __construct(
        string $username,
        string $privateKeyPath = '~/.ssh/id_rsa',
        string $passphrase = '',
        ?string $certificatePath = null
    ) {
        $this->username = $username;
        $this->privateKeyPath = $privateKeyPath;
        $this->passphrase = $passphrase;
        $this->certificatePath = $certificatePath;
    }

    public function authenticate(
        BinaryPacketHandler $handler,
        string $sessionId,
        ?Cancellation $cancellation = null
    ): void {
        if (!exists($this->privateKeyPath)) {
            throw new AuthenticationFailureException('Private key does not exist at path: ' . $this->privateKeyPath);
        }

        $key = PrivateKeyLoader::load(read($this->privateKeyPath), $this->passphrase);
        $key = $this->withCertificate($key);

        // The server's EXT_INFO arrives around here, and readMessage() absorbs
        // it on the way, which is what lets the key pick an algorithm the
        // server will take.
        $this->requestUserAuthService($handler, $cancellation);

        $algorithm = $key->getSignatureAlgorithm($this->serverSignatureAlgorithms);
        $publicKey = $key->getPublicKeyBlob();

        $request = new UserAuthRequestAskPublicKey();
        $request->username = $this->username;
        $request->authType = UserAuthRequest::TYPE_PUBLIC_KEY;
        $request->keyAlgorithm = $algorithm;
        $request->keyBlob = $publicKey;

        $handler->write($request);

        // The offer is refused before anything is signed, so this says the key
        // is unknown to the server rather than that the key is broken.
        if (!$this->readMessage($handler, $cancellation) instanceof UserAuthPkOk) {
            throw new PublicKeyNotAcceptedException(\sprintf(
                'The server does not accept the public key in %s for user %s: '
                    . 'it is not in authorized_keys, or its algorithm is not permitted.',
                $this->privateKeyPath,
                $this->username
            ));
        }

        $signatureRequest = new UserAuthRequestSignedPublicKey();
        $signatureRequest->username = $this->username;
        $signatureRequest->authType = UserAuthRequest::TYPE_PUBLIC_KEY;
        $signatureRequest->keyAlgorithm = $algorithm;
        $signatureRequest->keyBlob = $publicKey;

        // What gets signed is the session identifier followed by the request
        // as it will go out, minus the signature itself.
        $signatureRaw = \pack(
            'Na*a*',
            \strlen($sessionId),
            $sessionId,
            $signatureRequest->encode()
        );

        $signature = $key->sign($signatureRaw, $algorithm);
        $signatureFormat = $key->getSignatureFormat($algorithm);

        $signatureRequest->signature = \pack(
            'Na*Na*',
            \strlen($signatureFormat),
            $signatureFormat,
            \strlen($signature),
            $signature
        );

        $handler->write($signatureRequest);
        $packet = $this->readMessage($handler, $cancellation);

        // The server was willing to take this key and then turned the signature
        // down, which is a different problem from not knowing the key at all.
        if ($packet instanceof UserAuthFailure) {
            throw new AuthenticationFailureException(\sprintf(
                'The server rejected the signature made with %s.',
                $this->privateKeyPath
            ));
        }

        if ($packet === null) {
            throw new AuthenticationFailureException('Connection closed during authentication');
        }
    }

    /**
     * Wraps the key in its certificate, if there is one to find.
     *
     * An explicitly given path is an error when missing; the conventional
     * "<key>-cert.pub" beside the private key is used only when present, so
     * that keys without a certificate keep working unchanged.
     */
    private function withCertificate(SigningKey $key): SigningKey {
        $path = $this->certificatePath ?? $this->privateKeyPath . '-cert.pub';

        if (!exists($path)) {
            if ($this->certificatePath !== null) {
                throw new AuthenticationFailureException('Certificate does not exist at path: ' . $path);
            }

            return $key;
        }

        return new CertifiedKey($key, self::decodeCertificate(read($path), $path));
    }

    /**
     * A certificate file looks like a public key line: type, base64 blob and
     * an optional comment.
     */
    private static function decodeCertificate(string $contents, string $path): string {
        $fields = \preg_split('/\s+/', \trim($contents));

        if (\count($fields) < 2) {
            throw new AuthenticationFailureException('Could not read a certificate from ' . $path);
        }

        $blob = \base64_decode($fields[1], true);

        if ($blob === false) {
            throw new AuthenticationFailureException('The certificate in ' . $path . ' is not valid base64');
        }

        return $blob;
    }
}
