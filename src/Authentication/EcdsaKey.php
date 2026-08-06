<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Ssh\Internal\Ecdsa;

/**
 * An ECDSA key over one of the three NIST curves of RFC 5656.
 *
 * The curve fixes everything: there is one algorithm name and one digest per
 * curve, so nothing is negotiated. OpenSSL returns the signature as DER, which
 * has to be re-encoded as the two mpints SSH expects.
 *
 * @internal
 */
final class EcdsaKey implements SigningKey {
    private \OpenSSLAsymmetricKey $key;

    private string $curve;

    private string $publicKeyBlob;

    public function __construct(\OpenSSLAsymmetricKey $key, string $curve, string $point) {
        $this->key = $key;
        $this->curve = $curve;
        $this->publicKeyBlob = Ecdsa::publicKeyBlob($curve, $point);
    }

    public function getSignatureAlgorithm(array $serverSignatureAlgorithms): string {
        $algorithm = Ecdsa::algorithmFor($this->curve);

        // An empty list means the server never sent EXT_INFO, which says
        // nothing about whether it accepts this algorithm - only newer servers
        // advertise at all, so silence is not a refusal.
        if ($serverSignatureAlgorithms !== [] && !\in_array($algorithm, $serverSignatureAlgorithms, true)) {
            throw new AuthenticationFailureException(\sprintf(
                'Server does not accept %s. Server accepts: %s.',
                $algorithm,
                \implode(', ', $serverSignatureAlgorithms)
            ));
        }

        return $algorithm;
    }

    public function getSignatureFormat(string $algorithm): string {
        return $algorithm;
    }

    public function getPublicKeyBlob(): string {
        return $this->publicKeyBlob;
    }

    public function sign(string $data, string $algorithm): string {
        if ($algorithm !== Ecdsa::algorithmFor($this->curve)) {
            throw new AuthenticationFailureException(\sprintf(
                'Cannot sign with %s using a %s key',
                $algorithm,
                $this->curve
            ));
        }

        \openssl_sign($data, $derSignature, $this->key, Ecdsa::digestFor($this->curve));

        return Ecdsa::signatureToSsh($derSignature);
    }
}
