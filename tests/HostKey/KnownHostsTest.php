<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\HostKey;

use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\HostKey\HostKeyVerificationException;
use Amp\Ssh\HostKey\KnownHosts;

/**
 * known_hosts lookups, including the hashed entries OpenSSH writes by default.
 */
class KnownHostsTest extends AsyncTestCase {
    private string $path;

    private string $key;

    protected function setUp(): void {
        parent::setUp();

        $this->path = \sys_get_temp_dir() . '/amphp-ssh-known-hosts-' . \bin2hex(\random_bytes(8));
        $this->key = \pack('Na*', 7, 'ssh-rsa') . \random_bytes(140);
    }

    protected function tearDown(): void {
        if (\file_exists($this->path)) {
            \unlink($this->path);
        }

        parent::tearDown();
    }

    private function write(string ...$lines): void {
        \file_put_contents($this->path, \implode("\n", $lines) . "\n");
    }

    private function encoded(?string $key = null): string {
        return \base64_encode($key ?? $this->key);
    }

    private function hashedPattern(string $host): string {
        $salt = \random_bytes(20);

        return '|1|' . \base64_encode($salt) . '|' . \base64_encode(\hash_hmac('sha1', $host, $salt, true));
    }

    public function testKnownHostOnDefaultPort() {
        $this->write('example.com ssh-rsa ' . $this->encoded());

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);

        self::assertTrue(true, 'A matching entry must be accepted');
    }

    /**
     * OpenSSH only brackets the host when the port is not 22.
     */
    public function testKnownHostOnNonDefaultPort() {
        $this->write('[example.com]:2222 ssh-rsa ' . $this->encoded());

        (new KnownHosts($this->path))->verify('example.com', 2222, 'ssh-rsa', $this->key);

        self::assertTrue(true, 'The bracketed host:port form must be recognised');
    }

    public function testHashedEntry() {
        $this->write($this->hashedPattern('example.com') . ' ssh-rsa ' . $this->encoded());

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);

        self::assertTrue(true, 'Hashed entries must be matched, they are the default');
    }

    public function testCommaSeparatedPatternsAndWildcards() {
        $this->write('other.example.com,*.internal ssh-rsa ' . $this->encoded());

        (new KnownHosts($this->path))->verify('host.internal', 22, 'ssh-rsa', $this->key);

        self::assertTrue(true, 'Wildcard patterns must be honoured');
    }

    /**
     * The whole point: a host we know, presenting a key we do not.
     */
    public function testChangedKeyIsRejected() {
        $this->write('example.com ssh-rsa ' . $this->encoded(\random_bytes(140)));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/does not match the one recorded/');

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);
    }

    public function testUnknownHostIsRejectedByDefault() {
        $this->write('someone.else ssh-rsa ' . $this->encoded());

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/not listed/');

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);
    }

    public function testUnknownHostCanBeAllowedExplicitly() {
        $this->write('someone.else ssh-rsa ' . $this->encoded());

        (new KnownHosts($this->path, false))->verify('example.com', 22, 'ssh-rsa', $this->key);

        self::assertTrue(true, 'With rejectUnknown disabled an absent host is not an error');
    }

    /**
     * A changed key must still be caught even when unknown hosts are tolerated.
     */
    public function testChangedKeyIsRejectedEvenWhenUnknownHostsAreAllowed() {
        $this->write('example.com ssh-rsa ' . $this->encoded(\random_bytes(140)));

        $this->expectException(HostKeyVerificationException::class);

        (new KnownHosts($this->path, false))->verify('example.com', 22, 'ssh-rsa', $this->key);
    }

    public function testRevokedKeyIsRejected() {
        $this->write('@revoked example.com ssh-rsa ' . $this->encoded());

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/revoked/');

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);
    }

    /**
     * A CA line authorises certificates, not plain keys: a host presenting an
     * ordinary key still has to have an ordinary entry.
     */
    public function testCertificateAuthorityEntryDoesNotAuthoriseAPlainKey() {
        $this->write('@cert-authority example.com ssh-rsa ' . $this->encoded());

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/not listed/');

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);
    }

    /**
     * Conversely, a certificate is worthless without a CA to vouch for it.
     */
    public function testCertificateWithoutAnAuthorityIsRefused() {
        $factory = new CertificateFactory();
        $this->write('example.com ssh-rsa ' . $this->encoded());

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/no @cert-authority/');

        (new KnownHosts($this->path))->verify(
            'example.com',
            22,
            'ssh-ed25519-cert-v01@openssh.com',
            $factory->certificate()
        );
    }

    public function testCertificateSignedByATrustedAuthorityIsAccepted() {
        $factory = new CertificateFactory();
        $this->write($factory->authorityLine());

        (new KnownHosts($this->path))->verify(
            'example.com',
            22,
            'ssh-ed25519-cert-v01@openssh.com',
            $factory->certificate()
        );

        self::assertTrue(true, 'A certificate from a listed authority must be accepted');
    }

    /**
     * The CA line has to cover the host being connected to, not just exist.
     */
    public function testCertificateAuthorityForAnotherHostDoesNotApply() {
        $factory = new CertificateFactory();
        $this->write($factory->authorityLine('other.example.org'));

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/no @cert-authority/');

        (new KnownHosts($this->path))->verify(
            'example.com',
            22,
            'ssh-ed25519-cert-v01@openssh.com',
            $factory->certificate()
        );
    }

    public function testCertificateFromAnUntrustedAuthorityIsRefused() {
        $factory = new CertificateFactory();
        $other = new CertificateFactory();

        // The file trusts a different CA than the one that signed.
        $this->write($other->authorityLine());

        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/not trusted here/');

        (new KnownHosts($this->path))->verify(
            'example.com',
            22,
            'ssh-ed25519-cert-v01@openssh.com',
            $factory->certificate()
        );
    }

    public function testCommentsAndBlankLinesAreIgnored() {
        $this->write('', '# a comment', 'example.com ssh-rsa ' . $this->encoded(), '');

        (new KnownHosts($this->path))->verify('example.com', 22, 'ssh-rsa', $this->key);

        self::assertTrue(true);
    }

    public function testMissingFileIsRejected() {
        $this->expectException(HostKeyVerificationException::class);
        $this->expectExceptionMessageMatches('/No known_hosts file/');

        (new KnownHosts($this->path . '-absent'))->verify('example.com', 22, 'ssh-rsa', $this->key);
    }
}
