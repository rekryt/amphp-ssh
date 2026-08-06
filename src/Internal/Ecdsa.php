<?php declare(strict_types=1);

namespace Amp\Ssh\Internal;

use function Amp\Ssh\Transport\read_mpint;
use function Amp\Ssh\Transport\read_string;

/**
 * The ECDSA details SSH and OpenSSL disagree about.
 *
 * RFC 5656 names each curve twice - once as an SSH algorithm and once as a
 * curve identifier - and carries the signature as two mpints, while OpenSSL
 * speaks OIDs and DER. Everything needed to translate lives here.
 *
 * @internal
 */
final class Ecdsa {
    /**
     * SSH curve identifier to the OpenSSL curve name, digest and field size.
     *
     * The field size is what an EC point coordinate is padded to; getting it
     * wrong produces a public key the server does not recognise.
     */
    private const CURVES = [
        'nistp256' => ['openssl' => 'prime256v1', 'digest' => OPENSSL_ALGO_SHA256, 'size' => 32],
        'nistp384' => ['openssl' => 'secp384r1', 'digest' => OPENSSL_ALGO_SHA384, 'size' => 48],
        'nistp521' => ['openssl' => 'secp521r1', 'digest' => OPENSSL_ALGO_SHA512, 'size' => 66],
    ];

    /** OpenSSL curve name to SSH curve identifier. */
    private const OPENSSL_CURVES = [
        'prime256v1' => 'nistp256',
        'secp256r1' => 'nistp256',
        'secp384r1' => 'nistp384',
        'secp521r1' => 'nistp521',
    ];

    /** OID 1.2.840.10045.2.1, id-ecPublicKey. */
    private const OID_EC_PUBLIC_KEY = "\x2a\x86\x48\xce\x3d\x02\x01";

    /** Curve OIDs, by SSH curve identifier. */
    private const CURVE_OIDS = [
        'nistp256' => "\x2a\x86\x48\xce\x3d\x03\x01\x07",
        'nistp384' => "\x2b\x81\x04\x00\x22",
        'nistp521' => "\x2b\x81\x04\x00\x23",
    ];

    public static function isSupportedCurve(string $curve): bool {
        return isset(self::CURVES[$curve]);
    }

    /**
     * @return string[] SSH algorithm names, strongest curve first.
     */
    public static function algorithms(): array {
        return ['ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256'];
    }

    public static function algorithmFor(string $curve): string {
        return 'ecdsa-sha2-' . $curve;
    }

    /**
     * The curve an ecdsa-sha2-* algorithm name refers to.
     */
    public static function curveFor(string $algorithm): ?string {
        $curve = \substr($algorithm, \strlen('ecdsa-sha2-'));

        return \str_starts_with($algorithm, 'ecdsa-sha2-') && isset(self::CURVES[$curve]) ? $curve : null;
    }

    public static function digestFor(string $curve): int {
        return self::curve($curve)['digest'];
    }

    public static function fieldSize(string $curve): int {
        return self::curve($curve)['size'];
    }

    public static function curveFromOpenSsl(string $name): ?string {
        return self::OPENSSL_CURVES[$name] ?? null;
    }

    /**
     * Builds the SSH public key blob: algorithm, curve, then the point.
     */
    public static function publicKeyBlob(string $curve, string $point): string {
        return \pack('Na*', \strlen(self::algorithmFor($curve)), self::algorithmFor($curve))
            . \pack('Na*', \strlen($curve), $curve)
            . \pack('Na*', \strlen($point), $point);
    }

    /**
     * An uncompressed EC point, 0x04 followed by both coordinates padded to
     * the field size.
     */
    public static function point(string $curve, string $x, string $y): string {
        $size = self::fieldSize($curve);

        return "\x04" . self::pad($x, $size) . self::pad($y, $size);
    }

    /**
     * Turns the DER signature OpenSSL produces into the SSH encoding.
     *
     * OpenSSL returns SEQUENCE { INTEGER r, INTEGER s }; SSH wants the two
     * values as mpints inside a string of their own.
     */
    public static function signatureToSsh(string $derSignature): string {
        [$tag, $contents] = Der::read($derSignature);

        if ($tag !== Der::TAG_SEQUENCE) {
            throw new \RuntimeException('Expected a DER SEQUENCE from the ECDSA signature');
        }

        $r = Der::readInteger($contents);
        $s = Der::readInteger($contents);

        return \pack('Na*', \strlen(self::mpint($r)), self::mpint($r))
            . \pack('Na*', \strlen(self::mpint($s)), self::mpint($s));
    }

    /**
     * The reverse: an SSH signature blob back into DER for openssl_verify().
     */
    public static function signatureFromSsh(string $sshSignature): string {
        $blob = $sshSignature;
        $r = read_mpint($blob);
        $s = read_mpint($blob);

        return Der::sequence(Der::integer($r) . Der::integer($s));
    }

    /**
     * A PEM public key OpenSSL will accept, built from an SSH point.
     */
    public static function publicKeyToPem(string $curve, string $point): string {
        $algorithm = Der::sequence(
            Der::tagged(Der::TAG_OID, self::OID_EC_PUBLIC_KEY)
            . Der::tagged(Der::TAG_OID, self::CURVE_OIDS[$curve])
        );

        $der = Der::sequence($algorithm . Der::tagged(Der::TAG_BIT_STRING, "\x00" . $point));

        return Der::pem($der, 'PUBLIC KEY');
    }

    /**
     * A PEM private key from the raw scalar, for keys that arrive in the
     * openssh-key-v1 container rather than as PEM already.
     */
    public static function privateKeyToPem(string $curve, string $scalar, string $point): string {
        $der = Der::sequence(
            Der::integer("\x01")
            . Der::tagged(Der::TAG_OCTET_STRING, self::pad($scalar, self::fieldSize($curve)))
            . Der::contextTag(0, Der::tagged(Der::TAG_OID, self::CURVE_OIDS[$curve]))
            . Der::contextTag(1, Der::tagged(Der::TAG_BIT_STRING, "\x00" . $point))
        );

        return Der::pem($der, 'EC PRIVATE KEY');
    }

    /**
     * Reads curve and point out of an SSH public key blob.
     *
     * @return array{0: string, 1: string} Curve identifier and point.
     */
    public static function splitPublicKeyBlob(string $blob): array {
        read_string($blob); // algorithm name
        $curve = read_string($blob);
        $point = read_string($blob);

        return [$curve, $point];
    }

    private static function curve(string $curve): array {
        if (!isset(self::CURVES[$curve])) {
            throw new \RuntimeException(\sprintf('Unsupported EC curve: %s', $curve));
        }

        return self::CURVES[$curve];
    }

    private static function pad(string $value, int $size): string {
        $value = \ltrim($value, "\x00");

        return \str_pad($value, $size, "\x00", STR_PAD_LEFT);
    }

    /**
     * SSH mpints are signed, so a high leading bit needs a zero byte in front.
     */
    private static function mpint(string $value): string {
        $value = \ltrim($value, "\x00");

        if ($value === '') {
            return '';
        }

        return (\ord($value[0]) & 0x80) !== 0 ? "\x00" . $value : $value;
    }
}
