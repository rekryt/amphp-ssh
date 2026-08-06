<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\HostKey;

use Amp\Ssh\HostKey\HostKeySignature;
use Amp\Ssh\HostKey\HostKeyVerificationException;
use PHPUnit\Framework\TestCase;

/**
 * Host key signature checking.
 *
 * The client used to accept any host key without looking at the signature at
 * all, which made the key a claim rather than a proof.
 */
class HostKeySignatureTest extends TestCase {
    /** @var resource|\OpenSSLAsymmetricKey */
    private $privateKey;

    private string $hostKeyBlob;

    protected function setUp(): void {
        parent::setUp();

        $this->privateKey = \openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($this->privateKey === false) {
            self::markTestSkipped('OpenSSL cannot generate an RSA key here');
        }

        $details = \openssl_pkey_get_details($this->privateKey);

        $this->hostKeyBlob = self::sshString('ssh-rsa')
            . self::sshString(self::mpint($details['rsa']['e']))
            . self::sshString(self::mpint($details['rsa']['n']));
    }

    private static function sshString(string $value): string {
        return \pack('Na*', \strlen($value), $value);
    }

    private static function mpint(string $value): string {
        return (\ord($value[0]) & 0x80) !== 0 ? "\x00" . $value : $value;
    }

    private function sign(string $data, int $algorithm): string {
        \openssl_sign($data, $signature, $this->privateKey, $algorithm);

        return $signature;
    }

    public function provideAlgorithms(): iterable {
        yield 'rsa-sha2-512' => ['rsa-sha2-512', OPENSSL_ALGO_SHA512];
        yield 'rsa-sha2-256' => ['rsa-sha2-256', OPENSSL_ALGO_SHA256];
        yield 'ssh-rsa' => ['ssh-rsa', OPENSSL_ALGO_SHA1];
    }

    /**
     * @dataProvider provideAlgorithms
     */
    public function testValidSignature(string $format, int $algorithm) {
        $exchangeHash = \random_bytes(32);

        HostKeySignature::verify(
            $this->hostKeyBlob,
            $this->sign($exchangeHash, $algorithm),
            $format,
            $exchangeHash
        );

        self::assertTrue(true, 'A signature made with the matching key must be accepted');
    }

    /**
     * The case that matters: somebody in the middle presenting a key they do
     * not hold, or replaying a signature over a different exchange.
     */
    public function testSignatureOverDifferentDataIsRejected() {
        $signature = $this->sign(\random_bytes(32), OPENSSL_ALGO_SHA512);

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/does not hold the private key/');

        HostKeySignature::verify($this->hostKeyBlob, $signature, 'rsa-sha2-512', \random_bytes(32));
    }

    public function testTamperedSignatureIsRejected() {
        $exchangeHash = \random_bytes(32);
        $signature = $this->sign($exchangeHash, OPENSSL_ALGO_SHA512);
        $signature[10] = $signature[10] === "\x00" ? "\x01" : "\x00";

        $this->expectException(HostKeyVerificationException::class);

        HostKeySignature::verify($this->hostKeyBlob, $signature, 'rsa-sha2-512', $exchangeHash);
    }

    /**
     * A signature verified with the wrong digest must not pass.
     */
    public function testDigestMismatchIsRejected() {
        $exchangeHash = \random_bytes(32);
        $signature = $this->sign($exchangeHash, OPENSSL_ALGO_SHA256);

        $this->expectException(HostKeyVerificationException::class);

        HostKeySignature::verify($this->hostKeyBlob, $signature, 'rsa-sha2-512', $exchangeHash);
    }

    public function testSignatureFromAnotherKeyIsRejected() {
        $exchangeHash = \random_bytes(32);
        $other = \openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        \openssl_sign($exchangeHash, $signature, $other, OPENSSL_ALGO_SHA512);

        $this->expectException(HostKeyVerificationException::class);

        HostKeySignature::verify($this->hostKeyBlob, $signature, 'rsa-sha2-512', $exchangeHash);
    }

    /**
     * ssh-dss is not implemented; being told so beats being silently accepted.
     */
    public function testUnsupportedFormatIsRefusedRatherThanIgnored() {
        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/RSA, ECDSA and Ed25519 host keys/');

        HostKeySignature::verify($this->hostKeyBlob, 'signature', 'ssh-dss', 'hash');
    }

    /**
     * @dataProvider provideCurves
     */
    public function testValidEcdsaSignature(string $curve, string $opensslCurve, int $digest) {
        $key = \openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $opensslCurve]);

        if ($key === false) {
            self::markTestSkipped('OpenSSL cannot generate a key on ' . $opensslCurve);
        }

        $details = \openssl_pkey_get_details($key);
        $blob = \Amp\Ssh\Internal\Ecdsa::publicKeyBlob(
            $curve,
            \Amp\Ssh\Internal\Ecdsa::point($curve, $details['ec']['x'], $details['ec']['y'])
        );

        $signed = \random_bytes(32);
        \openssl_sign($signed, $der, $key, $digest);

        HostKeySignature::verify($blob, \Amp\Ssh\Internal\Ecdsa::signatureToSsh($der), 'ecdsa-sha2-' . $curve, $signed);

        self::assertTrue(true, 'A valid ECDSA host key signature must be accepted');
    }

    public function provideCurves(): iterable {
        yield 'nistp256' => ['nistp256', 'prime256v1', OPENSSL_ALGO_SHA256];
        yield 'nistp384' => ['nistp384', 'secp384r1', OPENSSL_ALGO_SHA384];
        yield 'nistp521' => ['nistp521', 'secp521r1', OPENSSL_ALGO_SHA512];
    }

    public function testEcdsaSignatureFromAnotherKeyIsRejected() {
        $make = static function (): array {
            $key = \openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            $details = \openssl_pkey_get_details($key);

            return [$key, \Amp\Ssh\Internal\Ecdsa::publicKeyBlob(
                'nistp256',
                \Amp\Ssh\Internal\Ecdsa::point('nistp256', $details['ec']['x'], $details['ec']['y'])
            )];
        };

        [, $blob] = $make();
        [$otherKey] = $make();

        if ($otherKey === false) {
            self::markTestSkipped('OpenSSL cannot generate an EC key here');
        }

        $signed = \random_bytes(32);
        \openssl_sign($signed, $der, $otherKey, OPENSSL_ALGO_SHA256);

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/does not hold the private key/');

        HostKeySignature::verify($blob, \Amp\Ssh\Internal\Ecdsa::signatureToSsh($der), 'ecdsa-sha2-nistp256', $signed);
    }

    /**
     * The curve is part of the algorithm name, so a key on a different curve
     * than the signature claims must be refused rather than tried.
     */
    public function testEcdsaCurveMismatchIsRejected() {
        $key = \openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        if ($key === false) {
            self::markTestSkipped('OpenSSL cannot generate an EC key here');
        }

        $details = \openssl_pkey_get_details($key);
        $blob = \Amp\Ssh\Internal\Ecdsa::publicKeyBlob(
            'nistp256',
            \Amp\Ssh\Internal\Ecdsa::point('nistp256', $details['ec']['x'], $details['ec']['y'])
        );

        $this->expectException(HostKeyVerificationException::class);

        HostKeySignature::verify($blob, 'signature', 'ecdsa-sha2-nistp384', 'hash');
    }

    public function testKeyFormatMustMatchSignatureFormat() {
        $blob = self::sshString('ssh-ed25519') . self::sshString(\random_bytes(32));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/does not match/');

        HostKeySignature::verify($blob, 'signature', 'rsa-sha2-512', 'hash');
    }

    public function testValidEd25519Signature() {
        [$publicKey, $privateKey] = self::ed25519Pair();

        $exchangeHash = \random_bytes(32);
        $blob = self::sshString('ssh-ed25519') . self::sshString($publicKey);

        HostKeySignature::verify(
            $blob,
            \sodium_crypto_sign_detached($exchangeHash, $privateKey),
            'ssh-ed25519',
            $exchangeHash
        );

        self::assertTrue(true, 'A valid Ed25519 host key signature must be accepted');
    }

    public function testEd25519SignatureFromAnotherKeyIsRejected() {
        [$publicKey] = self::ed25519Pair();
        [, $otherPrivate] = self::ed25519Pair();

        $exchangeHash = \random_bytes(32);
        $blob = self::sshString('ssh-ed25519') . self::sshString($publicKey);

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/does not hold the private key/');

        HostKeySignature::verify(
            $blob,
            \sodium_crypto_sign_detached($exchangeHash, $otherPrivate),
            'ssh-ed25519',
            $exchangeHash
        );
    }

    public function testEd25519KeyOfTheWrongLengthIsRejected() {
        $blob = self::sshString('ssh-ed25519') . self::sshString(\random_bytes(16));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/must be 32 bytes/');

        HostKeySignature::verify($blob, \str_repeat("\x00", 64), 'ssh-ed25519', 'hash');
    }

    /**
     * @return array{0: string, 1: string} Public and secret key.
     */
    private static function ed25519Pair(): array {
        $pair = \sodium_crypto_sign_keypair();

        return [\sodium_crypto_sign_publickey($pair), \sodium_crypto_sign_secretkey($pair)];
    }
}
