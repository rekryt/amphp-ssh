<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Negotiator;

use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Message\ExtInfo;
use Amp\Ssh\Message\KeyExchangeInit;
use Amp\Ssh\Negotiator;
use Amp\Ssh\Tests\Channel\FakeHandler;

/**
 * Algorithm negotiation, without a server.
 *
 * Covers what the client offers and how it reacts to a server that offers
 * nothing in common - the case that used to surface much later as an
 * unrelated "Invalid reply" from the key exchange.
 */
class AlgorithmNegotiationTest extends AsyncTestCase {
    private function serverKex(array $overrides = []): KeyExchangeInit {
        $kex = new KeyExchangeInit();
        $kex->cookie = \random_bytes(16);
        $kex->kexAlgorithms = ['curve25519-sha256@libssh.org'];
        $kex->serverHostKeyAlgorithms = ['rsa-sha2-512', 'ssh-ed25519'];
        $kex->encryptionAlgorithmsClientToServer = ['aes128-ctr'];
        $kex->encryptionAlgorithmsServerToClient = ['aes128-ctr'];
        $kex->macAlgorithmsClientToServer = ['hmac-sha2-256'];
        $kex->macAlgorithmsServerToClient = ['hmac-sha2-256'];
        $kex->compressionAlgorithmsClientToServer = ['none'];
        $kex->compressionAlgorithmsServerToClient = ['none'];

        foreach ($overrides as $field => $value) {
            $kex->{$field} = $value;
        }

        return $kex;
    }

    private function clientKexSentTo(FakeHandler $handler): KeyExchangeInit {
        foreach ($handler->written as $message) {
            if ($message instanceof KeyExchangeInit) {
                return $message;
            }
        }

        self::fail('The client never sent a KEXINIT');
    }

    /**
     * Runs negotiation far enough to capture the client's KEXINIT.
     *
     * The peer hangs up straight after its KEXINIT: a fake transport cannot
     * answer the key exchange itself, and without the disconnect the client
     * would wait for a reply that never comes. Negotiation therefore always
     * ends in a failure here, which is the point of interest for half these
     * tests and irrelevant noise for the other half.
     */
    private function negotiateAgainst(KeyExchangeInit $serverKex): array {
        $handler = new FakeHandler();
        $handler->deliver($serverKex);
        $handler->disconnect();

        $negotiator = Negotiator::create();
        $failure = null;

        try {
            $negotiator->negotiate($handler, 'SSH-2.0-Fake', 'SSH-2.0-AmpSSH_0.1');
        } catch (\Throwable $exception) {
            $failure = $exception;
        }

        return [$handler, $failure];
    }

    /**
     * A server with no cipher in common says so, naming both lists.
     *
     * Key exchange and host keys were checked this way; ciphers and MACs were
     * not. Their intersection went through current(), which answers false when
     * there is nothing in it, and false as an array key is 0 - so the failure
     * arrived as "Undefined array key 0" from inside the negotiator, naming
     * neither the algorithm nor the two lists that failed to meet.
     *
     * @dataProvider unmatchableAlgorithms
     */
    public function testNoCommonAlgorithmIsReportedNamingBothLists(array $overrides, string $expected) {
        [, $failure] = $this->negotiateAgainst($this->serverKex($overrides));

        self::assertNotNull($failure, 'Negotiation should have failed');
        self::assertStringContainsString('No common', $failure->getMessage());
        self::assertStringContainsString($expected, $failure->getMessage());
    }

    public function unmatchableAlgorithms(): array {
        return [
            'server to client cipher' => [
                ['encryptionAlgorithmsServerToClient' => ['nothing-we-support']],
                'server to client encryption',
            ],
            'client to server cipher' => [
                ['encryptionAlgorithmsClientToServer' => ['nothing-we-support']],
                'client to server encryption',
            ],
            'server to client MAC' => [
                ['macAlgorithmsServerToClient' => ['nothing-we-support']],
                'server to client MAC',
            ],
            'client to server MAC' => [
                ['macAlgorithmsClientToServer' => ['nothing-we-support']],
                'client to server MAC',
            ],
        ];
    }

    public function testClientOffersOnlyVerifiableHostKeyAlgorithms() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        $offered = $this->clientKexSentTo($handler)->serverHostKeyAlgorithms;

        $plain = \array_values(\array_filter(
            $offered,
            static fn (string $algorithm): bool => !\str_contains($algorithm, '-cert-v01@')
        ));

        self::assertSame(
            [
                'ssh-ed25519',
                'ecdsa-sha2-nistp521',
                'ecdsa-sha2-nistp384',
                'ecdsa-sha2-nistp256',
                'rsa-sha2-512',
                'rsa-sha2-256',
                'ssh-rsa',
            ],
            $plain,
            'Current OpenSSH refuses ssh-rsa, so the SHA-2 names must be offered and preferred'
        );
    }

    /**
     * A host with a certificate can be trusted through its CA rather than
     * through an entry for that particular machine, so certificates go first.
     */
    public function testCertificateAlgorithmsAreOfferedFirst() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        $offered = $this->clientKexSentTo($handler)->serverHostKeyAlgorithms;

        self::assertStringContainsString('-cert-v01@openssh.com', $offered[0]);
        self::assertContains('ssh-ed25519-cert-v01@openssh.com', $offered);
    }

    /**
     * Adding a certificate to a host must not quietly change which algorithm
     * gets picked, so the two lists have to rank the same way.
     */
    public function testCertificateOrderMirrorsThePlainOrder() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        $offered = $this->clientKexSentTo($handler)->serverHostKeyAlgorithms;

        $strip = static fn (string $algorithm): string => \str_replace('-cert-v01@openssh.com', '', $algorithm);

        $certificates = \array_map($strip, \array_values(\array_filter(
            $offered,
            static fn (string $a): bool => \str_contains($a, '-cert-v01@')
        )));

        $plain = \array_values(\array_filter(
            $offered,
            static fn (string $a): bool => !\str_contains($a, '-cert-v01@')
        ));

        self::assertSame($plain, $certificates);
    }

    /**
     * Preference order, not just membership: a server offering both must not
     * be talked into SHA-1 or into the smallest group.
     */
    public function testStrongestKeyExchangeIsPreferred() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        $offered = $this->clientKexSentTo($handler)->kexAlgorithms;

        $groups = \array_values(\array_filter(
            $offered,
            static fn (string $a): bool => \str_starts_with($a, 'diffie-hellman-')
        ));

        self::assertSame(
            [
                'diffie-hellman-group18-sha512',
                'diffie-hellman-group16-sha512',
                'diffie-hellman-group14-sha256',
                'diffie-hellman-group14-sha1',
            ],
            $groups
        );
    }

    public function testStrongestCipherIsPreferred() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        $ciphers = $this->clientKexSentTo($handler)->encryptionAlgorithmsClientToServer;

        self::assertSame('chacha20-poly1305@openssh.com', $ciphers[0]);
        self::assertLessThan(
            \array_search('aes256-cbc', $ciphers, true),
            \array_search('aes256-ctr', $ciphers, true),
            'CTR must be preferred over CBC'
        );
    }

    /**
     * Offering an algorithm whose signature cannot be checked means accepting
     * that host key on the server's word alone.
     */
    public function testClientDoesNotOfferSshDss() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        self::assertNotContains('ssh-dss', $this->clientKexSentTo($handler)->serverHostKeyAlgorithms);
    }

    /**
     * Without this indicator the server never sends EXT_INFO, and the client
     * has no way to learn which signature algorithms are acceptable.
     */
    public function testClientAdvertisesExtInfo() {
        [$handler] = $this->negotiateAgainst($this->serverKex());

        self::assertContains('ext-info-c', $this->clientKexSentTo($handler)->kexAlgorithms);
    }

    public function testNoCommonHostKeyAlgorithmIsReportedWithBothLists() {
        [, $failure] = $this->negotiateAgainst($this->serverKex([
            // Neither is offered: ssh-dss has no verification behind it and the
            // security key variants are not implemented.
            'serverHostKeyAlgorithms' => ['ssh-dss', 'sk-ssh-ed25519@openssh.com'],
        ]));

        self::assertInstanceOf(\RuntimeException::class, $failure);
        self::assertStringContainsString('No common server host key algorithm', $failure->getMessage());
        self::assertStringContainsString('rsa-sha2-512', $failure->getMessage());
        self::assertStringContainsString('ssh-dss', $failure->getMessage());
    }

    public function testNoCommonKeyExchangeAlgorithmIsReported() {
        [, $failure] = $this->negotiateAgainst($this->serverKex([
            'kexAlgorithms' => ['sntrup761x25519-sha512@openssh.com'],
        ]));

        self::assertInstanceOf(\RuntimeException::class, $failure);
        self::assertStringContainsString('No common key exchange algorithm', $failure->getMessage());
    }

    /**
     * ext-info-c is an indicator, never a usable algorithm. A server echoing it
     * back must not make the client try to look it up.
     */
    public function testExtInfoIndicatorIsNeverSelectedAsAnAlgorithm() {
        [, $failure] = $this->negotiateAgainst($this->serverKex([
            'kexAlgorithms' => ['ext-info-c'],
        ]));

        self::assertInstanceOf(\RuntimeException::class, $failure);
        self::assertStringContainsString('No common key exchange algorithm', $failure->getMessage());
    }

    public function testExtInfoDecodesServerSignatureAlgorithms() {
        $algorithms = 'rsa-sha2-512,rsa-sha2-256,ssh-ed25519';
        $payload = \pack(
            'CNNa*Na*',
            ExtInfo::getNumber(),
            1,
            \strlen('server-sig-algs'),
            'server-sig-algs',
            \strlen($algorithms),
            $algorithms
        );

        $message = ExtInfo::decode($payload);

        self::assertSame(
            ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'],
            $message->getServerSignatureAlgorithms()
        );
    }

    public function testExtInfoWithoutServerSignatureAlgorithms() {
        $payload = \pack('CN', ExtInfo::getNumber(), 0);

        self::assertSame([], ExtInfo::decode($payload)->getServerSignatureAlgorithms());
    }
}
