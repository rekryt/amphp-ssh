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
     * ECDSA client keys, which 1.x could not use at all.
     *
     * This asserted the opposite until now - that an ECDSA key was refused -
     * and went on passing after support was added, because the refusal it saw
     * was the server not knowing the key rather than the client failing to use
     * it. The test container does install tests/key_ecdsa.pub, so the two
     * reasons finally came apart and the stale expectation failed.
     */
    public function testEcdsaSuccess() {
        $sshResource = $this->connectWithInstalledKey('key_ecdsa');

        self::assertInstanceOf(SshResource::class, $sshResource);

        $sshResource->close();
    }
}
