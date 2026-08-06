<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

/**
 * An RSA key, signing with SHA-1 or SHA-2 depending on what the server takes.
 *
 * @internal
 */
final class RsaKey implements SigningKey {
    /** Preference order; current OpenSSH accepts only the SHA-2 variants. */
    private const ALGORITHMS = [
        'rsa-sha2-512' => OPENSSL_ALGO_SHA512,
        'rsa-sha2-256' => OPENSSL_ALGO_SHA256,
        'ssh-rsa' => OPENSSL_ALGO_SHA1,
    ];

    private \OpenSSLAsymmetricKey $key;

    private string $publicKeyBlob;

    public function __construct(\OpenSSLAsymmetricKey $key, array $details) {
        $this->key = $key;

        // The blob keeps the ssh-rsa layout whichever signature algorithm ends
        // up being used; only the algorithm name and the signature change.
        $this->publicKeyBlob = \pack('Na*', \strlen('ssh-rsa'), 'ssh-rsa')
            . self::mpint($details['rsa']['e'])
            . self::mpint($details['rsa']['n']);
    }

    public function getSignatureAlgorithm(array $serverSignatureAlgorithms): string {
        // No EXT_INFO means a server older than RFC 8308, which only knows the
        // SHA-1 based name.
        if ($serverSignatureAlgorithms === []) {
            return 'ssh-rsa';
        }

        foreach (\array_keys(self::ALGORITHMS) as $algorithm) {
            if (\in_array($algorithm, $serverSignatureAlgorithms, true)) {
                return $algorithm;
            }
        }

        throw new AuthenticationFailureException(\sprintf(
            'Server accepts none of the RSA signature algorithms this client implements. Server accepts: %s.',
            \implode(', ', $serverSignatureAlgorithms)
        ));
    }

    public function getSignatureFormat(string $algorithm): string {
        return $algorithm;
    }

    public function getPublicKeyBlob(): string {
        return $this->publicKeyBlob;
    }

    public function sign(string $data, string $algorithm): string {
        if (!isset(self::ALGORITHMS[$algorithm])) {
            throw new AuthenticationFailureException('Cannot sign with ' . $algorithm . ' using an RSA key');
        }

        \openssl_sign($data, $signature, $this->key, self::ALGORITHMS[$algorithm]);

        return $signature;
    }

    private static function mpint(string $value): string {
        if ((\ord($value[0]) & 0x80) !== 0) {
            $value = \chr(0) . $value;
        }

        return \pack('Na*', \strlen($value), $value);
    }
}
