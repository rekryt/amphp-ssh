<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\HostKey;

use Amp\Ssh\HostKey\Certificate;
use Amp\Ssh\HostKey\HostKeyVerificationException;
use PHPUnit\Framework\TestCase;

/**
 * OpenSSH host certificates.
 *
 * A certificate lets a host be trusted through its authority rather than
 * through an entry of its own, which is only worth anything if every one of
 * the checks below actually happens.
 */
class CertificateTest extends TestCase {
    private CertificateFactory $factory;

    protected function setUp(): void {
        parent::setUp();

        $this->factory = new CertificateFactory();
    }

    private function trustFactoryAuthority(): callable {
        return fn (string $key): bool => $key === $this->factory->authorityPublicKey;
    }

    public function testValidCertificate() {
        $certificate = Certificate::parse($this->factory->certificate());

        $certificate->validate('example.com', $this->trustFactoryAuthority());

        self::assertSame('test-cert', $certificate->getKeyId());
        self::assertSame(['example.com'], $certificate->getPrincipals());
    }

    /**
     * The exchange is signed by the key inside the certificate, so that key has
     * to come back out in its plain form.
     */
    public function testCarriedPublicKey() {
        $certificate = Certificate::parse($this->factory->certificate());

        self::assertSame(
            CertificateFactory::blob($this->factory->hostPublicKey),
            $certificate->getPublicKey()
        );
    }

    /**
     * A user certificate presented as a host key would let anyone with a user
     * certificate impersonate a server.
     */
    public function testUserCertificateIsRefused() {
        $certificate = Certificate::parse($this->factory->certificate(type: 1));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/user certificate/');

        $certificate->validate('example.com', $this->trustFactoryAuthority());
    }

    public function testExpiredCertificateIsRefused() {
        $certificate = Certificate::parse($this->factory->certificate(
            validAfter: \time() - 7200,
            validBefore: \time() - 3600
        ));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/expired/');

        $certificate->validate('example.com', $this->trustFactoryAuthority());
    }

    public function testCertificateNotYetValidIsRefused() {
        $certificate = Certificate::parse($this->factory->certificate(
            validAfter: \time() + 3600,
            validBefore: \time() + 7200
        ));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/not valid until/');

        $certificate->validate('example.com', $this->trustFactoryAuthority());
    }

    public function testWrongPrincipalIsRefused() {
        $certificate = Certificate::parse($this->factory->certificate(['other.example.org']));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/issued for/');

        $certificate->validate('example.com', $this->trustFactoryAuthority());
    }

    public function testPrincipalPatternsAreHonoured() {
        $certificate = Certificate::parse($this->factory->certificate(['*.example.com']));

        $certificate->validate('host.example.com', $this->trustFactoryAuthority());

        self::assertTrue(true, 'A wildcard principal must match');
    }

    /**
     * OpenSSH treats an empty principal list as "any host"; worth having a test
     * so the behaviour is deliberate rather than accidental.
     */
    public function testEmptyPrincipalListMatchesAnyHost() {
        $certificate = Certificate::parse($this->factory->certificate([]));

        $certificate->validate('anything.example', $this->trustFactoryAuthority());

        self::assertTrue(true);
    }

    public function testUntrustedAuthorityIsRefused() {
        $certificate = Certificate::parse($this->factory->certificate());

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/not trusted here/');

        $certificate->validate('example.com', static fn (string $key): bool => false);
    }

    /**
     * The check that matters most: a certificate whose signature was not made
     * by the authority it names.
     */
    public function testForgedSignatureIsRefused() {
        $certificate = Certificate::parse($this->factory->certificate(signWithAnotherKey: true));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/does not hold the private key/');

        $certificate->validate('example.com', $this->trustFactoryAuthority());
    }

    public function testTamperedBodyIsRefused() {
        $blob = $this->factory->certificate();

        // Flip a byte inside the key id, which is covered by the signature.
        $position = \strpos($blob, 'test-cert');
        $blob[$position] = 'T';

        $certificate = Certificate::parse($blob);

        $this->expectException(HostKeyVerificationException::class);

        $certificate->validate('example.com', $this->trustFactoryAuthority());
    }

    public function testGarbageIsReportedAsMalformed() {
        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/Malformed host certificate/');

        Certificate::parse(\pack('Na*', 4, 'junk'));
    }

    public function testAlgorithmRecognition() {
        self::assertTrue(Certificate::isCertificateAlgorithm('ssh-ed25519-cert-v01@openssh.com'));
        self::assertTrue(Certificate::isCertificateAlgorithm('rsa-sha2-512-cert-v01@openssh.com'));
        self::assertFalse(Certificate::isCertificateAlgorithm('ssh-ed25519'));

        self::assertSame('ssh-ed25519', Certificate::underlyingAlgorithm('ssh-ed25519-cert-v01@openssh.com'));
        self::assertSame(
            'ecdsa-sha2-nistp384',
            Certificate::underlyingAlgorithm('ecdsa-sha2-nistp384-cert-v01@openssh.com')
        );
    }
}
