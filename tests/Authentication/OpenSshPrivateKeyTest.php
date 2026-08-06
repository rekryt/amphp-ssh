<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Authentication;

use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\OpenSshPrivateKey;
use function Amp\Ssh\Transport\read_string;
use PHPUnit\Framework\TestCase;

/**
 * The openssh-key-v1 container, which is the only shape an Ed25519 key comes
 * in and which OpenSSL cannot read.
 */
class OpenSshPrivateKeyTest extends TestCase {
    private function keyPath(string $name): string {
        return __DIR__ . '/../' . $name;
    }

    public function testRecognisesItsOwnFormat() {
        self::assertTrue(OpenSshPrivateKey::looksLikeOne(\file_get_contents($this->keyPath('key_ed25519'))));
    }

    public function testDoesNotClaimPemKeys() {
        self::assertFalse(OpenSshPrivateKey::looksLikeOne(\file_get_contents($this->keyPath('key_rsa'))));
        self::assertFalse(OpenSshPrivateKey::looksLikeOne(\file_get_contents($this->keyPath('key_ecdsa'))));
    }

    public function testParsesEd25519() {
        $key = OpenSshPrivateKey::parse(\file_get_contents($this->keyPath('key_ed25519')));

        self::assertSame('ssh-ed25519', $key->getSignatureAlgorithm([]));
    }

    /**
     * The blob sent on the wire has to be byte for byte what ssh-keygen wrote
     * into the .pub file, otherwise the server will not recognise the key.
     */
    public function testPublicBlobMatchesTheCompanionPubFile() {
        $key = OpenSshPrivateKey::parse(\file_get_contents($this->keyPath('key_ed25519')));

        $fields = \explode(' ', \trim(\file_get_contents($this->keyPath('key_ed25519.pub'))));
        $expected = \base64_decode($fields[1], true);

        self::assertSame($expected, $key->getPublicKeyBlob());
    }

    public function testSignatureVerifiesAgainstThePublicKey() {
        $key = OpenSshPrivateKey::parse(\file_get_contents($this->keyPath('key_ed25519')));

        $message = \random_bytes(64);
        $signature = $key->sign($message, 'ssh-ed25519');

        $blob = $key->getPublicKeyBlob();
        read_string($blob); // key type
        $publicKey = read_string($blob);

        self::assertTrue(\sodium_crypto_sign_verify_detached($signature, $message, $publicKey));
    }

    private static function sshString(string $value): string {
        return \pack('Na*', \strlen($value), $value);
    }

    private static function armour(string $body): string {
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            . \chunk_split(\base64_encode($body), 70, "\n")
            . "-----END OPENSSH PRIVATE KEY-----\n";
    }

    /**
     * An unsupported key type inside a supported container must say so rather
     * than fail somewhere further down.
     */
    public function testUnsupportedKeyTypeIsReported() {
        $private = \pack('NN', 1, 1) . self::sshString('ssh-dss');

        $key = "openssh-key-v1\0"
            . self::sshString('none')
            . self::sshString('none')
            . self::sshString('')
            . \pack('N', 1)
            . self::sshString('public blob')
            . self::sshString($private);

        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/are not supported/');

        OpenSshPrivateKey::parse(self::armour($key));
    }

    public function testMismatchedChecksumIsReported() {
        $private = \pack('NN', 1, 2) . self::sshString('ssh-ed25519');

        $key = "openssh-key-v1\0"
            . self::sshString('none')
            . self::sshString('none')
            . self::sshString('')
            . \pack('N', 1)
            . self::sshString('public blob')
            . self::sshString($private);

        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/checksum/');

        OpenSshPrivateKey::parse(self::armour($key));
    }

    public function testEncryptedKeyIsRefusedWithInstructions() {
        $key = "openssh-key-v1\0"
            . self::sshString('aes256-ctr')
            . self::sshString('bcrypt')
            . self::sshString('salt-and-rounds');

        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/ssh-keygen -p/');

        OpenSshPrivateKey::parse(self::armour($key));
    }

    public function testGarbageIsRejected() {
        $this->expectException(AuthenticationFailureException::class);

        OpenSshPrivateKey::parse('not a key at all');
    }
}
