<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Ssh\HostKey\Certificate;
use function Amp\Ssh\Transport\read_string;

/**
 * A private key presented together with the certificate that vouches for it.
 *
 * A user certificate lets a server accept a key it has never seen, because a
 * certificate authority it does trust has signed it. On the wire that means
 * two names rather than one: the request advertises the certificate algorithm,
 * while the signature is still made - and named - with the plain key inside.
 * Getting those the wrong way round is the usual way this fails.
 *
 * @internal
 */
final class CertifiedKey implements SigningKey {
    private SigningKey $key;

    private string $certificate;

    private string $algorithm;

    public function __construct(SigningKey $key, string $certificate) {
        $blob = $certificate;
        $algorithm = read_string($blob);

        if (!Certificate::isCertificateAlgorithm($algorithm)) {
            throw new AuthenticationFailureException(\sprintf(
                'The certificate is of type %s, which is not an OpenSSH certificate.',
                $algorithm
            ));
        }

        $this->key = $key;
        $this->certificate = $certificate;
        $this->algorithm = $algorithm;
    }

    public function getSignatureAlgorithm(array $serverSignatureAlgorithms): string {
        // server-sig-algs lists plain signature algorithms; certificates are
        // not named there, so the underlying one is what has to be acceptable.
        $this->key->getSignatureAlgorithm($serverSignatureAlgorithms);

        return $this->algorithm;
    }

    public function getSignatureFormat(string $algorithm): string {
        return Certificate::underlyingAlgorithm($algorithm);
    }

    public function getPublicKeyBlob(): string {
        return $this->certificate;
    }

    public function sign(string $data, string $algorithm): string {
        return $this->key->sign($data, Certificate::underlyingAlgorithm($algorithm));
    }
}
