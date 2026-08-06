<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\HostKey;

use Amp\Ssh\HostKey\Certificate;

/**
 * Builds OpenSSH host certificates for the tests.
 *
 * Everything is Ed25519: it keeps the fixtures short and needs no OpenSSL, so
 * the tests still run where openssl_pkey_new() cannot find a configuration.
 */
final class CertificateFactory {
    public string $authorityPublicKey;

    private string $authoritySecretKey;

    public string $hostPublicKey;

    public function __construct() {
        $authority = \sodium_crypto_sign_keypair();
        $this->authorityPublicKey = self::blob(\sodium_crypto_sign_publickey($authority));
        $this->authoritySecretKey = \sodium_crypto_sign_secretkey($authority);

        $host = \sodium_crypto_sign_keypair();
        $this->hostPublicKey = \sodium_crypto_sign_publickey($host);
    }

    /** Wraps a raw Ed25519 public key in its SSH blob. */
    public static function blob(string $publicKey): string {
        return self::string('ssh-ed25519') . self::string($publicKey);
    }

    /**
     * @param string[] $principals
     */
    public function certificate(
        array $principals = ['example.com'],
        int $type = Certificate::HOST,
        ?int $validAfter = null,
        ?int $validBefore = null,
        bool $signWithAnotherKey = false
    ): string {
        $principalBlob = '';

        foreach ($principals as $principal) {
            $principalBlob .= self::string($principal);
        }

        $body = self::string('ssh-ed25519-cert-v01@openssh.com')
            . self::string(\random_bytes(32))          // nonce
            . self::string($this->hostPublicKey)       // pk
            . \pack('J', 1)                            // serial
            . \pack('N', $type)
            . self::string('test-cert')                // key id
            . self::string($principalBlob)
            . \pack('J', $validAfter ?? (\time() - 3600))
            . \pack('J', $validBefore ?? (\time() + 3600))
            . self::string('')                         // critical options
            . self::string('')                         // extensions
            . self::string('')                         // reserved
            . self::string($this->authorityPublicKey);

        $secretKey = $this->authoritySecretKey;

        if ($signWithAnotherKey) {
            $secretKey = \sodium_crypto_sign_secretkey(\sodium_crypto_sign_keypair());
        }

        $signature = \sodium_crypto_sign_detached($body, $secretKey);

        return $body . self::string(self::string('ssh-ed25519') . self::string($signature));
    }

    /** The base64 form a known_hosts line carries. */
    public function authorityLine(string $pattern = 'example.com'): string {
        return '@cert-authority ' . $pattern . ' ssh-ed25519 ' . \base64_encode($this->authorityPublicKey);
    }

    private static function string(string $value): string {
        return \pack('Na*', \strlen($value), $value);
    }
}
