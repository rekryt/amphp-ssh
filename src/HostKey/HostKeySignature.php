<?php declare(strict_types=1);

namespace Amp\Ssh\HostKey;

use Amp\Ssh\Internal\Der;
use Amp\Ssh\Internal\Ecdsa;
use function Amp\Ssh\Transport\read_mpint;
use function Amp\Ssh\Transport\read_string;

/**
 * Verifies that a peer holds the private half of the key it presented, by
 * checking its signature over some data - the exchange hash during a key
 * exchange, or a certificate body when a CA is involved.
 *
 * Without this a host key is just a claim: anybody in the middle can present a
 * key of their own. Checking the signature is what makes the key worth
 * comparing against known_hosts at all - and, conversely, comparing a key we
 * never verified would be equally pointless. Both halves are required.
 *
 * @internal
 */
final class HostKeySignature {
    private const RSA_DIGESTS = [
        'ssh-rsa' => OPENSSL_ALGO_SHA1,
        'rsa-sha2-256' => OPENSSL_ALGO_SHA256,
        'rsa-sha2-512' => OPENSSL_ALGO_SHA512,
    ];

    private const ED25519 = 'ssh-ed25519';

    private const ED25519_KEY_LENGTH = 32;

    private const ED25519_SIGNATURE_LENGTH = 64;

    /** OID 1.2.840.113549.1.1.1, rsaEncryption. */
    private const OID_RSA_ENCRYPTION = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    /**
     * @param string $hostKey   Key blob as sent by the peer.
     * @param string $signature Signature bytes, without the format name.
     * @param string $format    Signature format, e.g. rsa-sha2-512.
     * @param string $signed    The data the signature is made over.
     *
     * @throws HostKeyVerificationException When the signature does not hold up.
     */
    public static function verify(string $hostKey, string $signature, string $format, string $signed): void {
        if ($format === self::ED25519) {
            self::verifyEd25519($hostKey, $signature, $signed);

            return;
        }

        if (Ecdsa::curveFor($format) !== null) {
            self::verifyEcdsa($hostKey, $signature, $format, $signed);

            return;
        }

        if (!isset(self::RSA_DIGESTS[$format])) {
            throw new HostKeyVerificationException(\sprintf(
                'Cannot verify a %s signature; this client implements RSA, ECDSA and Ed25519 host keys.',
                $format
            ));
        }

        self::verifyRsa($hostKey, $signature, $format, $signed);
    }

    /**
     * Ed25519 needs no key reconstruction: the blob carries the raw 32 byte
     * public key and libsodium takes it as is.
     */
    private static function verifyEd25519(string $hostKey, string $signature, string $signed): void {
        $blob = $hostKey;
        $keyFormat = read_string($blob);

        self::assertKeyFormat($keyFormat, self::ED25519, self::ED25519);

        $publicKey = read_string($blob);

        if (\strlen($publicKey) !== self::ED25519_KEY_LENGTH) {
            throw new HostKeyVerificationException(\sprintf(
                'Ed25519 host key must be %d bytes, got %d.',
                self::ED25519_KEY_LENGTH,
                \strlen($publicKey)
            ));
        }

        if (\strlen($signature) !== self::ED25519_SIGNATURE_LENGTH) {
            throw new HostKeyVerificationException(\sprintf(
                'Ed25519 signature must be %d bytes, got %d.',
                self::ED25519_SIGNATURE_LENGTH,
                \strlen($signature)
            ));
        }

        if (!\sodium_crypto_sign_verify_detached($signature, $signed, $publicKey)) {
            throw self::mismatch();
        }
    }

    /**
     * The curve is part of the algorithm name, so a key on a different curve
     * than the signature claims is a mismatch rather than a detail.
     */
    private static function verifyEcdsa(string $hostKey, string $signature, string $format, string $signed): void {
        $expectedCurve = Ecdsa::curveFor($format);

        $blob = $hostKey;
        $keyFormat = read_string($blob);

        self::assertKeyFormat($keyFormat, $format, $format);

        $curve = read_string($blob);
        $point = read_string($blob);

        if ($curve !== $expectedCurve) {
            throw new HostKeyVerificationException(\sprintf(
                'Host key is on curve %s but the signature claims %s.',
                $curve,
                $expectedCurve
            ));
        }

        $publicKey = \openssl_pkey_get_public(Ecdsa::publicKeyToPem($curve, $point));

        if ($publicKey === false) {
            throw new HostKeyVerificationException('Server host key could not be parsed as an EC public key.');
        }

        $result = \openssl_verify(
            $signed,
            Ecdsa::signatureFromSsh($signature),
            $publicKey,
            Ecdsa::digestFor($curve)
        );

        if ($result !== 1) {
            throw self::mismatch();
        }
    }

    private static function verifyRsa(string $hostKey, string $signature, string $format, string $signed): void {
        $blob = $hostKey;
        $keyFormat = read_string($blob);

        // RFC 8332 reuses the ssh-rsa key format for the SHA-2 signatures.
        self::assertKeyFormat($keyFormat, 'ssh-rsa', $format);

        $e = read_mpint($blob);
        $n = read_mpint($blob);

        $publicKey = \openssl_pkey_get_public(self::rsaToPem($n, $e));

        if ($publicKey === false) {
            throw new HostKeyVerificationException('Server host key could not be parsed as an RSA public key.');
        }

        if (\openssl_verify($signed, $signature, $publicKey, self::RSA_DIGESTS[$format]) !== 1) {
            throw self::mismatch();
        }
    }

    private static function assertKeyFormat(string $actual, string $expected, string $signatureFormat): void {
        if ($actual !== $expected) {
            throw new HostKeyVerificationException(\sprintf(
                'Host key is in %s format, which does not match the %s signature.',
                $actual,
                $signatureFormat
            ));
        }
    }

    private static function mismatch(): HostKeyVerificationException {
        return new HostKeyVerificationException(
            'Host key signature is invalid: the peer does not hold the private key it presented. '
                . 'This is what a man-in-the-middle looks like.'
        );
    }

    /**
     * Builds a PEM public key out of the raw modulus and exponent.
     *
     * OpenSSL cannot be handed RSA components directly from PHP, so the
     * SubjectPublicKeyInfo structure has to be assembled by hand.
     */
    private static function rsaToPem(string $modulus, string $exponent): string {
        $rsaPublicKey = Der::sequence(Der::integer($modulus) . Der::integer($exponent));

        $algorithm = Der::sequence(
            Der::tagged(Der::TAG_OID, self::OID_RSA_ENCRYPTION) . "\x05\x00"
        );

        $der = Der::sequence($algorithm . Der::tagged(Der::TAG_BIT_STRING, "\x00" . $rsaPublicKey));

        return Der::pem($der, 'PUBLIC KEY');
    }
}
