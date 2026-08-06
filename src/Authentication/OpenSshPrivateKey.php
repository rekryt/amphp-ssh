<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Ssh\Internal\Ecdsa;
use function Amp\Ssh\Transport\read_mpint;
use function Amp\Ssh\Transport\read_string;
use function Amp\Ssh\Transport\read_uint32;

/**
 * Reads the "openssh-key-v1" private key container.
 *
 * ssh-keygen has written this format by default for years, and it is the only
 * format an Ed25519 key comes in - OpenSSL cannot read it, which is why such a
 * key used to be rejected as "Private Key Format is not supported".
 *
 * Encrypted keys are refused rather than half-handled: unwrapping them needs
 * bcrypt_pbkdf, which is not implemented here.
 *
 * @internal
 */
final class OpenSshPrivateKey {
    private const MAGIC = "openssh-key-v1\0";

    private const ED25519 = 'ssh-ed25519';

    public static function looksLikeOne(string $contents): bool {
        return \str_contains($contents, '-----BEGIN OPENSSH PRIVATE KEY-----');
    }

    /**
     * @throws AuthenticationFailureException
     */
    public static function parse(string $contents): SigningKey {
        $body = self::decodeArmour($contents);

        if (\strncmp($body, self::MAGIC, \strlen(self::MAGIC)) !== 0) {
            throw new AuthenticationFailureException('Not an openssh-key-v1 private key.');
        }

        $payload = \substr($body, \strlen(self::MAGIC));

        $cipherName = read_string($payload);
        read_string($payload); // kdfname
        read_string($payload); // kdfoptions

        if ($cipherName !== 'none') {
            throw new AuthenticationFailureException(\sprintf(
                'The private key is encrypted with %s. Encrypted OpenSSH keys are not supported; '
                    . 'decrypt it first with: ssh-keygen -p -N "" -f <key>.',
                $cipherName
            ));
        }

        if (read_uint32($payload) !== 1) {
            throw new AuthenticationFailureException('Private key files holding several keys are not supported.');
        }

        $publicBlob = read_string($payload);
        $private = read_string($payload);

        // Two matching check integers are how the format signals a successful
        // decryption; for an unencrypted key they simply have to agree. Read
        // into locals: both are consumed from the same buffer by reference, so
        // comparing the calls inline would depend on evaluation order.
        $firstCheck = read_uint32($private);
        $secondCheck = read_uint32($private);

        if ($firstCheck !== $secondCheck) {
            throw new AuthenticationFailureException('Private key checksum mismatch.');
        }

        $type = read_string($private);

        if ($type === self::ED25519) {
            return self::ed25519($publicBlob, $private);
        }

        if (Ecdsa::curveFor($type) !== null) {
            return self::ecdsa($type, $publicBlob, $private);
        }

        if (\str_starts_with($type, 'sk-')) {
            throw new AuthenticationFailureException(\sprintf(
                'This is a %s key, which lives on a hardware security key. The file holds only a credential '
                    . 'handle - the signature has to be computed by the token itself, and PHP has no way to '
                    . 'talk to one. Use it through an agent instead: start ssh-agent, ssh-add the key, and '
                    . 'authenticate with %s.',
                $type,
                AgentAuthentication::class
            ));
        }

        throw new AuthenticationFailureException(\sprintf(
            'OpenSSH private keys of type %s are not supported; this client handles RSA, ECDSA and Ed25519.',
            $type
        ));
    }

    private static function ed25519(string $publicBlob, string $private): Ed25519Key {
        $publicKey = read_string($private);
        $secretKey = read_string($private);

        if (\strlen($publicKey) !== 32 || \strlen($secretKey) !== 64) {
            throw new AuthenticationFailureException('Malformed Ed25519 private key.');
        }

        return new Ed25519Key($publicBlob, $secretKey);
    }

    /**
     * OpenSSL cannot take a raw scalar, so the components are reassembled into
     * a PEM key for it.
     */
    private static function ecdsa(string $type, string $publicBlob, string $private): EcdsaKey {
        $curve = Ecdsa::curveFor($type);
        $storedCurve = read_string($private);
        $point = read_string($private);
        $scalar = read_mpint($private);

        if ($storedCurve !== $curve) {
            throw new AuthenticationFailureException(\sprintf(
                'Key claims to be %s but carries curve %s.',
                $type,
                $storedCurve
            ));
        }

        $key = \openssl_get_privatekey(Ecdsa::privateKeyToPem($curve, $scalar, $point));

        if ($key === false) {
            throw new AuthenticationFailureException('Could not rebuild the ECDSA private key.');
        }

        return new EcdsaKey($key, $curve, $point);
    }

    private static function decodeArmour(string $contents): string {
        $matched = \preg_match(
            '/-----BEGIN OPENSSH PRIVATE KEY-----(?<body>.*?)-----END OPENSSH PRIVATE KEY-----/s',
            $contents,
            $matches
        );

        if ($matched !== 1) {
            throw new AuthenticationFailureException('Could not find an OpenSSH private key block in the file.');
        }

        $decoded = \base64_decode(\preg_replace('/\s+/', '', $matches['body']), true);

        if ($decoded === false) {
            throw new AuthenticationFailureException('The OpenSSH private key block is not valid base64.');
        }

        return $decoded;
    }
}
