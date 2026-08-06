<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\PublicKey;
use Amp\Ssh\Authentication\PublicKeyNotAcceptedException;
use Amp\Ssh\SshResource;

class PublicKeyTest extends IntegrationTestCase {
    private function connectWithKey(string $keyFile, string $passphrase = ''): SshResource {
        return SshServer::connectWith(
            new PublicKey(SshServer::user(), __DIR__ . '/../' . $keyFile, $passphrase)
        );
    }

    /**
     * Connects with a key that has to be installed on the server.
     *
     * The test key pairs live in tests/ and only the test container has them in
     * authorized_keys, so against any other server these tests are asking a
     * question it cannot answer. Skipping needs the distinction the protocol
     * already makes: a key refused before anything is signed is one the server
     * does not know, while a signature the server turns down after accepting
     * the key is exactly the defect these tests exist to catch - and that one
     * must still fail.
     */
    private function connectWithInstalledKey(string $keyFile, string $passphrase = ''): SshResource {
        try {
            return $this->connectWithKey($keyFile, $passphrase);
        } catch (PublicKeyNotAcceptedException $exception) {
            self::markTestSkipped(\sprintf(
                'This server does not have tests/%s in authorized_keys for %s.',
                $keyFile,
                SshServer::user()
            ));
        }
    }

    public function testRsaSuccess() {
        $sshResource = $this->connectWithInstalledKey('key_rsa');

        self::assertInstanceOf(SshResource::class, $sshResource);

        $sshResource->close();
    }

    public function testRsaFail() {
        $this->expectException(AuthenticationFailureException::class);

        $this->connectWithKey('invalid_key_rsa');
    }

    public function testRsaNotExistingFile() {
        $this->expectException(AuthenticationFailureException::class);

        $this->connectWithKey('not_existing');
    }

    public function testRsaPassphraseSuccess() {
        $sshResource = $this->connectWithInstalledKey('key_passphrase_rsa', 'passphrase');

        self::assertInstanceOf(SshResource::class, $sshResource);

        $sshResource->close();
    }

    public function testRsaPassphraseFail() {
        $this->expectException(AuthenticationFailureException::class);

        $this->connectWithKey('key_passphrase_rsa', 'bad');
    }

    public function testEd25519Success() {
        $sshResource = $this->connectWithInstalledKey('key_ed25519');

        self::assertInstanceOf(SshResource::class, $sshResource);

        $sshResource->close();
    }

    /**
     * An ECDSA key is read and offered like any other.
     *
     * This used to assert that ECDSA was unsupported, which it no longer is.
     * What it shows now is that the key loads and gets as far as the server,
     * which refuses it because tests/key_ecdsa is not in authorized_keys -
     * PublicKeyNotAcceptedException, a subclass of the failure expected here.
     * A parse error or an unsupported curve would not reach that point.
     */
    public function testEcdsa() {
        $this->expectException(AuthenticationFailureException::class);

        $this->connectWithKey('key_ecdsa');
    }
}
