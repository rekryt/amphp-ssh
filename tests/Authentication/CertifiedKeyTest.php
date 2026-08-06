<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Authentication;

use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\CertifiedKey;
use Amp\Ssh\Authentication\Ed25519Key;
use Amp\Ssh\Authentication\OpenSshPrivateKey;
use Amp\Ssh\Tests\HostKey\CertificateFactory;
use PHPUnit\Framework\TestCase;

/**
 * A user certificate presented alongside the key it certifies.
 *
 * The whole subtlety is that two names are in play: the request advertises the
 * certificate, while the signature is made and named with the plain key. Using
 * one where the other belongs is the usual way this fails, and the server
 * rejects it with nothing more useful than "authentication failed".
 */
class CertifiedKeyTest extends TestCase {
    private function key(): Ed25519Key {
        $parsed = OpenSshPrivateKey::parse(\file_get_contents(__DIR__ . '/../key_ed25519'));

        self::assertInstanceOf(Ed25519Key::class, $parsed);

        return $parsed;
    }

    private function certificate(): string {
        return (new CertificateFactory())->certificate();
    }

    public function testAdvertisesTheCertificateAlgorithm() {
        $key = new CertifiedKey($this->key(), $this->certificate());

        self::assertSame('ssh-ed25519-cert-v01@openssh.com', $key->getSignatureAlgorithm([]));
    }

    /**
     * The signature is named after the plain key, not the certificate.
     */
    public function testSignatureIsNamedAfterThePlainKey() {
        $key = new CertifiedKey($this->key(), $this->certificate());

        self::assertSame('ssh-ed25519', $key->getSignatureFormat('ssh-ed25519-cert-v01@openssh.com'));
    }

    public function testPublicBlobIsTheCertificate() {
        $certificate = $this->certificate();
        $key = new CertifiedKey($this->key(), $certificate);

        self::assertSame($certificate, $key->getPublicKeyBlob());
    }

    /**
     * Signing has to reach the underlying key, which knows nothing about
     * certificates and would refuse the certificate algorithm name.
     */
    public function testSignsWithTheUnderlyingKey() {
        $plain = $this->key();
        $key = new CertifiedKey($plain, $this->certificate());

        $data = \random_bytes(64);

        self::assertSame(
            $plain->sign($data, 'ssh-ed25519'),
            $key->sign($data, 'ssh-ed25519-cert-v01@openssh.com')
        );
    }

    /**
     * server-sig-algs never lists certificate names, so the check has to be
     * made against the plain algorithm the certificate stands for.
     */
    public function testUnderlyingAlgorithmIsCheckedAgainstTheServer() {
        $key = new CertifiedKey($this->key(), $this->certificate());

        $this->expectException(AuthenticationFailureException::class);

        $key->getSignatureAlgorithm(['rsa-sha2-512']);
    }

    public function testAPlainKeyIsNotACertificate() {
        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/not an OpenSSH certificate/');

        new CertifiedKey($this->key(), CertificateFactory::blob(\random_bytes(32)));
    }
}
