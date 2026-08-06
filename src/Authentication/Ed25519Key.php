<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

/**
 * An Ed25519 key.
 *
 * One algorithm, one digest, nothing to negotiate - and no OpenSSL involved,
 * since these keys never come in a format it can read.
 *
 * @internal
 */
final class Ed25519Key implements SigningKey {
    public const ALGORITHM = 'ssh-ed25519';

    private string $publicKeyBlob;

    private string $secretKey;

    public function __construct(string $publicKeyBlob, string $secretKey) {
        $this->publicKeyBlob = $publicKeyBlob;
        $this->secretKey = $secretKey;
    }

    public function getSignatureAlgorithm(array $serverSignatureAlgorithms): string {
        if ($serverSignatureAlgorithms !== [] && !\in_array(self::ALGORITHM, $serverSignatureAlgorithms, true)) {
            throw new AuthenticationFailureException(\sprintf(
                'Server does not accept %s. Server accepts: %s.',
                self::ALGORITHM,
                \implode(', ', $serverSignatureAlgorithms)
            ));
        }

        return self::ALGORITHM;
    }

    public function getSignatureFormat(string $algorithm): string {
        return $algorithm;
    }

    public function getPublicKeyBlob(): string {
        return $this->publicKeyBlob;
    }

    public function sign(string $data, string $algorithm): string {
        if ($algorithm !== self::ALGORITHM) {
            throw new AuthenticationFailureException('Cannot sign with ' . $algorithm . ' using an Ed25519 key');
        }

        return \sodium_crypto_sign_detached($data, $this->secretKey);
    }
}
