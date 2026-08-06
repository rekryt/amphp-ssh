<?php declare(strict_types=1);

namespace Amp\Ssh\Internal;

/**
 * Just enough DER to bridge SSH and OpenSSL.
 *
 * PHP cannot build a key from its components, and OpenSSL hands back ECDSA
 * signatures in DER while SSH wants them as two mpints. Both directions need a
 * little ASN.1, and none of it is worth a dependency.
 *
 * @internal
 */
final class Der {
    public const TAG_INTEGER = 0x02;

    public const TAG_BIT_STRING = 0x03;

    public const TAG_OCTET_STRING = 0x04;

    public const TAG_OID = 0x06;

    public const TAG_SEQUENCE = 0x30;

    public static function sequence(string $contents): string {
        return self::tagged(self::TAG_SEQUENCE, $contents);
    }

    /**
     * Encodes a big-endian unsigned number as a DER INTEGER.
     */
    public static function integer(string $value): string {
        $value = \ltrim($value, "\x00");

        if ($value === '') {
            $value = "\x00";
        }

        // A leading bit of 1 would make the DER integer negative.
        if ((\ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return self::tagged(self::TAG_INTEGER, $value);
    }

    public static function tagged(int $tag, string $contents): string {
        return \chr($tag) . self::length(\strlen($contents)) . $contents;
    }

    /**
     * Context-specific constructed tag, as used for the optional fields of an
     * SEC1 private key.
     */
    public static function contextTag(int $number, string $contents): string {
        return self::tagged(0xA0 | $number, $contents);
    }

    public static function length(int $length): string {
        if ($length < 0x80) {
            return \chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = \chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }

        return \chr(0x80 | \strlen($bytes)) . $bytes;
    }

    /**
     * Reads one tag-length-value triple, advancing past it.
     *
     * @param string $der Consumed by reference.
     *
     * @return array{0: int, 1: string} Tag and contents.
     *
     * @throws \RuntimeException On anything malformed.
     */
    public static function read(string &$der): array {
        if ($der === '') {
            throw new \RuntimeException('Truncated DER: expected a tag');
        }

        $tag = \ord($der[0]);
        $offset = 1;

        if (!isset($der[$offset])) {
            throw new \RuntimeException('Truncated DER: expected a length');
        }

        $first = \ord($der[$offset++]);

        if ($first < 0x80) {
            $length = $first;
        } else {
            $count = $first & 0x7F;

            if ($count === 0 || $count > 4 || \strlen($der) < $offset + $count) {
                throw new \RuntimeException('Unsupported or truncated DER length');
            }

            $length = 0;

            for ($i = 0; $i < $count; ++$i) {
                $length = ($length << 8) | \ord($der[$offset++]);
            }
        }

        if (\strlen($der) < $offset + $length) {
            throw new \RuntimeException('Truncated DER: value shorter than its length');
        }

        $contents = \substr($der, $offset, $length);
        $der = \substr($der, $offset + $length);

        return [$tag, $contents];
    }

    /**
     * Reads a DER INTEGER as a big-endian unsigned byte string.
     */
    public static function readInteger(string &$der): string {
        [$tag, $contents] = self::read($der);

        if ($tag !== self::TAG_INTEGER) {
            throw new \RuntimeException(\sprintf('Expected a DER INTEGER, got tag 0x%02X', $tag));
        }

        return \ltrim($contents, "\x00") ?: "\x00";
    }

    public static function pem(string $der, string $label): string {
        return \sprintf(
            "-----BEGIN %s-----\n%s-----END %s-----\n",
            $label,
            \chunk_split(\base64_encode($der), 64, "\n"),
            $label
        );
    }
}
