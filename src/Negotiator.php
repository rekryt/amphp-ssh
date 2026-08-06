<?php declare(strict_types=1);

namespace Amp\Ssh;

use Amp\Cancellation;
use Amp\Ssh\Encryption\AeadCipher;
use Amp\Ssh\Encryption\Aes;
use Amp\Ssh\Encryption\AesGcm;
use Amp\Ssh\Encryption\ChaCha20Poly1305;
use Amp\Ssh\Encryption\Decryption;
use Amp\Ssh\Encryption\Encryption;
use Amp\Ssh\HostKey\Certificate;
use Amp\Ssh\HostKey\HostKeySignature;
use Amp\Ssh\KeyExchange\Curve25519Sha256;
use Amp\Ssh\KeyExchange\DiffieHellmanGroup;
use Amp\Ssh\KeyExchange\KeyExchange;
use Amp\Ssh\Mac\Hash;
use Amp\Ssh\Mac\Mac;
use Amp\Ssh\Message\KeyExchangeInit;
use Amp\Ssh\Message\Message;
use Amp\Ssh\Message\NewKeys;
use Amp\Ssh\Transport\BinaryPacketHandler;

/**
 * Negotiate algorithms to use for the ssh connection.
 *
 * @internal
 */
final class Negotiator {
    /** RFC 8308 indicator telling the server we understand SSH_MSG_EXT_INFO. */
    private const EXT_INFO_INDICATOR = 'ext-info-c';

    /**
     * Host key algorithm to the key blob format it actually carries.
     *
     * RFC 8332 reuses the ssh-rsa key format for the SHA-2 algorithms: only
     * the signature is named rsa-sha2-*, the public key inside KEXDH_REPLY
     * still says "ssh-rsa". Comparing the negotiated name against both fields,
     * as the original code did, therefore always fails for rsa-sha2-*.
     */
    private const HOST_KEY_FORMATS = [
        'ssh-ed25519' => 'ssh-ed25519',
        'ecdsa-sha2-nistp521' => 'ecdsa-sha2-nistp521',
        'ecdsa-sha2-nistp384' => 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp256' => 'ecdsa-sha2-nistp256',
        'rsa-sha2-512' => 'ssh-rsa',
        'rsa-sha2-256' => 'ssh-rsa',
        'ssh-rsa' => 'ssh-rsa',
    ];

    /** @var Decryption[] */
    private array $decryptions = [];

    /** @var Encryption[] */
    private array $encryptions = [];

    /** @var KeyExchange[] */
    private array $keyExchanges = [];

    /** @var Mac[] */
    private array $macs = [];

    private ?string $sessionId = null;

    /** Verified host key blob, for the trust check that follows. */
    private ?string $hostKey = null;

    private ?string $hostKeyFormat = null;

    private function addDecryption(Decryption $decryption): void {
        $this->decryptions[$decryption->getName()] = $decryption;
    }

    private function addEncryption(Encryption $encryption): void {
        $this->encryptions[$encryption->getName()] = $encryption;
    }

    private function addKeyExchange(KeyExchange $keyExchange): void {
        $this->keyExchanges[$keyExchange->getName()] = $keyExchange;
    }

    private function addMac(Mac $mac): void {
        $this->macs[$mac->getName()] = $mac;
    }

    public function getSessionId(): string {
        return $this->sessionId;
    }

    /**
     * The host key whose signature was verified during the exchange.
     */
    public function getHostKey(): string {
        if ($this->hostKey === null) {
            throw new \RuntimeException('No host key available before the key exchange has run');
        }

        return $this->hostKey;
    }

    public function getHostKeyFormat(): string {
        if ($this->hostKeyFormat === null) {
            throw new \RuntimeException('No host key available before the key exchange has run');
        }

        return $this->hostKeyFormat;
    }

    /**
     * Negotiate algorithms and install the derived keys on the handler.
     *
     * The handler is mutated in place: on return it encrypts and decrypts. If
     * this throws (including on cancellation) the handler is left half
     * negotiated and MUST NOT be used; the caller closes the connection.
     */
    public function negotiate(
        BinaryPacketHandler $binaryPacketHandler,
        string $serverIdentification,
        string $clientIdentification,
        ?Cancellation $cancellation = null
    ): BinaryPacketHandler {
        /*
        Key exchange will begin immediately after sending this identifier.
        All packets following the identification string SHALL use the binary
        packet protocol,
        */

        $serverKex = $binaryPacketHandler->read($cancellation);

        if (!$serverKex instanceof KeyExchangeInit) {
            throw new \RuntimeException('Invalid packet');
        }

        return $this->exchange($binaryPacketHandler, $serverKex, $serverIdentification, $clientIdentification, $cancellation);
    }

    /**
     * Runs a key re-exchange for a KEXINIT that has already been received.
     *
     * A server may ask for new keys at any point in a live session (OpenSSH
     * does so by volume and by time). The exchange is the same one as at the
     * start, with one difference that matters: the session identifier is fixed
     * at the first exchange and never changes, which is why sessionId is only
     * assigned when it is still unset.
     */
    public function rekey(
        BinaryPacketHandler $binaryPacketHandler,
        KeyExchangeInit $serverKex,
        string $serverIdentification,
        string $clientIdentification,
        ?Cancellation $cancellation = null
    ): BinaryPacketHandler {
        return $this->exchange($binaryPacketHandler, $serverKex, $serverIdentification, $clientIdentification, $cancellation);
    }

    private function exchange(
        BinaryPacketHandler $binaryPacketHandler,
        KeyExchangeInit $serverKex,
        string $serverIdentification,
        string $clientIdentification,
        ?Cancellation $cancellation
    ): BinaryPacketHandler {
        $clientKex = $this->createKeyExchange();
        $binaryPacketHandler->write($clientKex);

        // Negotiate
        $kex = $this->getKeyExchange($clientKex, $serverKex);
        $encrypt = $this->getEncrypt($clientKex, $serverKex);
        $decrypt = $this->getDecrypt($clientKex, $serverKex);
        $encryptMac = $this->getEncryptMac($clientKex, $serverKex);
        $decryptMac = $this->getDecryptMac($clientKex, $serverKex);

        // Settled before the exchange, not after: if there is no common host
        // key algorithm the connection is already doomed, and saying so here
        // beats a full round trip followed by a misleading "Invalid reply".
        $serverHostKeyAlgorithm = $this->getServerHostKey($clientKex, $serverKex);
        $isCertificate = Certificate::isCertificateAlgorithm($serverHostKeyAlgorithm);

        // With a certificate the blob is the certificate itself, while the
        // exchange is still signed by the key inside it - so the two formats
        // to expect are different things.
        $expectedSignatureFormat = $isCertificate
            ? Certificate::underlyingAlgorithm($serverHostKeyAlgorithm)
            : $serverHostKeyAlgorithm;

        $expectedKeyFormat = $isCertificate
            ? $serverHostKeyAlgorithm
            : (self::HOST_KEY_FORMATS[$serverHostKeyAlgorithm] ?? $serverHostKeyAlgorithm);

        /** @var Message $exchangeSend */
        /** @var Message $exchangeReceive */
        [$key, $exchangeSend, $exchangeReceive] = $kex->exchange($binaryPacketHandler, $cancellation);

        /*
        The hash H is computed as the HASH hash of the concatenation of the
        following:

            string    V_C, the client's identification string (CR and LF
                    excluded)
            string    V_S, the server's identification string (CR and LF
                    excluded)
            string    I_C, the payload of the client's SSH_MSG_KEXINIT
            string    I_S, the payload of the server's SSH_MSG_KEXINIT
            string    K_S, the host key
            mpint     e, exchange value sent by the client
            mpint     f, exchange value sent by the server
            mpint     K, the shared secret
         */

        $clientKexPayload = $clientKex->encode();
        $serverKexPayload = $serverKex->encode();

        $exchangeHash = \pack(
            'Na*Na*Na*Na*Na*Na*Na*Na*',
            \strlen($clientIdentification),
            $clientIdentification,
            \strlen($serverIdentification),
            $serverIdentification,
            \strlen($clientKexPayload),
            $clientKexPayload,
            \strlen($serverKexPayload),
            $serverKexPayload,
            \strlen($kex->getHostKey($exchangeReceive)),
            $kex->getHostKey($exchangeReceive),
            \strlen($kex->getEBytes($exchangeSend)),
            $kex->getEBytes($exchangeSend),
            \strlen($kex->getFBytes($exchangeReceive)),
            $kex->getFBytes($exchangeReceive),
            \strlen($key),
            $key
        );

        $exchangeHash = $kex->hash($exchangeHash);

        if ($this->sessionId === null) {
            $this->sessionId = $exchangeHash;
        }

        if ($expectedSignatureFormat !== $exchangeReceive->signatureFormat) {
            throw new \RuntimeException(\sprintf(
                'Server signed with %s but %s was negotiated',
                $exchangeReceive->signatureFormat,
                $expectedSignatureFormat
            ));
        }

        if ($expectedKeyFormat !== $exchangeReceive->hostKeyFormat) {
            throw new \RuntimeException(\sprintf(
                'Server host key is in %s format, expected %s for %s',
                $exchangeReceive->hostKeyFormat,
                $expectedKeyFormat,
                $serverHostKeyAlgorithm
            ));
        }

        // Proves the peer holds the private half of the key it presented. Until
        // this was added the host key was an unchecked claim and the client
        // would happily complete a handshake with anybody.
        //
        // A certificate signs with the key it certifies, so the signature is
        // checked against that key; whether the certificate itself is worth
        // anything is decided afterwards, by the host key verifier.
        HostKeySignature::verify(
            $isCertificate
                ? Certificate::parse($exchangeReceive->hostKey)->getPublicKey()
                : $exchangeReceive->hostKey,
            $exchangeReceive->signatureBlob,
            $exchangeReceive->signatureFormat,
            $exchangeHash
        );

        $this->hostKey = $exchangeReceive->hostKey;
        $this->hostKeyFormat = $exchangeReceive->hostKeyFormat;

        $binaryPacketHandler->write(new NewKeys());
        $binaryPacketHandler->read($cancellation);

        $key = \pack('Na*', \strlen($key), $key);

        $createDerivationKey = function (string $type, int $length) use ($kex, $key, $exchangeHash): string {
            $derivation = $kex->hash($key . $exchangeHash . $type . $this->sessionId);

            while ($length > \strlen($derivation)) {
                $derivation .= $kex->hash($key . $exchangeHash . $derivation);
            }

            return \substr($derivation, 0, $length);
        };

        // An AEAD cipher takes a nonce, not an IV the size of its block: for
        // AES-GCM that is 12 bytes against a 16 byte block. Deriving the block
        // size worth of material would silently produce the wrong nonce.
        $encrypt->resetEncrypt(
            $createDerivationKey('C', $encrypt->getKeySize()),
            $createDerivationKey('A', self::ivSize($encrypt))
        );

        $decrypt->resetDecrypt(
            $createDerivationKey('D', $decrypt->getKeySize()),
            $createDerivationKey('B', self::ivSize($decrypt))
        );

        $encryptMac->setKey($createDerivationKey('E', $encryptMac->getLength()));
        $decryptMac->setKey($createDerivationKey('F', $decryptMac->getLength()));

        $binaryPacketHandler->updateEncryption($encrypt, $encryptMac);
        $binaryPacketHandler->updateDecryption($decrypt, $decryptMac);

        return $binaryPacketHandler;
    }

    private function getDecrypt(KeyExchangeInit $clientKex, KeyExchangeInit $serverKex): Decryption {
        return $this->decryptions[self::negotiateName(
            'server to client encryption',
            $clientKex->encryptionAlgorithmsServerToClient,
            $serverKex->encryptionAlgorithmsServerToClient
        )];
    }

    private function getEncrypt(KeyExchangeInit $clientKex, KeyExchangeInit $serverKex): Encryption {
        return $this->encryptions[self::negotiateName(
            'client to server encryption',
            $clientKex->encryptionAlgorithmsClientToServer,
            $serverKex->encryptionAlgorithmsClientToServer
        )];
    }

    private function getKeyExchange(KeyExchangeInit $clientKex, KeyExchangeInit $serverKex): KeyExchange {
        $keyExchangeName = self::negotiateName(
            'key exchange',
            // ext-info-c is an RFC 8308 indicator, not an algorithm; a server
            // must never echo it back, but do not trust it to behave.
            \array_values(\array_diff($clientKex->kexAlgorithms, [self::EXT_INFO_INDICATOR])),
            $serverKex->kexAlgorithms
        );

        return $this->keyExchanges[$keyExchangeName];
    }

    private function getServerHostKey(KeyExchangeInit $clientKex, KeyExchangeInit $serverKex): string {
        return self::negotiateName(
            'server host key',
            $clientKex->serverHostKeyAlgorithms,
            $serverKex->serverHostKeyAlgorithms
        );
    }

    /**
     * Picks the first client-preferred name the server also offers.
     *
     * An empty intersection used to fall through as `false` and resurface much
     * later as an unrelated error - typically "Invalid reply" from the key
     * exchange, after the server had already disconnected. Naming both lists
     * turns that into a diagnosis.
     */
    private static function negotiateName(string $what, array $client, array $server): string {
        $common = \array_intersect($client, $server);

        if ($common === []) {
            throw new \RuntimeException(\sprintf(
                'No common %s algorithm. Client offers: %s. Server offers: %s.',
                $what,
                \implode(', ', $client) ?: '(none)',
                \implode(', ', $server) ?: '(none)'
            ));
        }

        return (string) \current($common);
    }

    private function getDecryptMac(KeyExchangeInit $clientKex, KeyExchangeInit $serverKex): Mac {
        return clone $this->macs[self::negotiateName(
            'server to client MAC',
            $clientKex->macAlgorithmsServerToClient,
            $serverKex->macAlgorithmsServerToClient
        )];
    }

    private function getEncryptMac(KeyExchangeInit $clientKex, KeyExchangeInit $serverKex): Mac {
        return clone $this->macs[self::negotiateName(
            'client to server MAC',
            $clientKex->macAlgorithmsClientToServer,
            $serverKex->macAlgorithmsClientToServer
        )];
    }

    private function createKeyExchange(): KeyExchangeInit {
        $clientKex = new KeyExchangeInit();
        $clientKex->cookie = \random_bytes(16);
        $clientKex->kexAlgorithms = \array_merge(
            \array_keys($this->keyExchanges),
            // Asks the server for SSH_MSG_EXT_INFO, which is how it tells us
            // which signature algorithms publickey auth may use (RFC 8308).
            [self::EXT_INFO_INDICATOR]
        );
        // Only algorithms whose signature this client can actually verify are
        // offered. ssh-dss used to be in this list without any verification
        // behind it, which meant advertising a host key we would have accepted
        // on nothing but the server's word; it is also 1024-bit DSA, disabled
        // by OpenSSH since 7.0.
        //
        // Certificates come first, as they do in OpenSSH: a host that has one
        // can be trusted through its CA rather than through a known_hosts
        // entry for that particular machine.
        $clientKex->serverHostKeyAlgorithms = \array_merge(
            Certificate::algorithms(),
            [
                'ssh-ed25519',
                'ecdsa-sha2-nistp521',
                'ecdsa-sha2-nistp384',
                'ecdsa-sha2-nistp256',
                // RFC 8332. Current OpenSSH refuses ssh-rsa (RSA/SHA-1)
                // outright, so the SHA-2 names must be offered and preferred.
                'rsa-sha2-512',
                'rsa-sha2-256',
                'ssh-rsa',
            ]
        );
        $clientKex->encryptionAlgorithmsClientToServer = \array_keys($this->encryptions);
        $clientKex->encryptionAlgorithmsServerToClient = \array_keys($this->decryptions);
        $clientKex->macAlgorithmsServerToClient = \array_keys($this->macs);
        $clientKex->macAlgorithmsClientToServer = \array_keys($this->macs);
        $clientKex->compressionAlgorithmsServerToClient = $clientKex->compressionAlgorithmsClientToServer = [
            'none',
        ];

        return $clientKex;
    }

    public static function create() {
        $negotiator = new static();
        foreach (self::supportedKeyExchanges() as $keyExchange) {
            $negotiator->addKeyExchange($keyExchange);
        }

        foreach (self::supportedEncryptions() as $algorithm) {
            $negotiator->addEncryption($algorithm);
        }

        foreach (self::supportedDecryptions() as $algorithm) {
            $negotiator->addDecryption($algorithm);
        }

        foreach (self::supportedMacs() as $algorithm) {
            $negotiator->addMac($algorithm);
        }

        return $negotiator;
    }

    public static function supportedKeyExchanges() {
        return \array_merge([new Curve25519Sha256()], DiffieHellmanGroup::create());
    }

    public static function supportedEncryptions() {
        // AEAD first: it is what current servers prefer, and it authenticates
        // the packet itself rather than relying on a bolted-on MAC.
        // ChaCha20-Poly1305 leads because it also hides the packet length.
        return \array_merge([new ChaCha20Poly1305()], AesGcm::create(), Aes::create());
    }

    public static function supportedDecryptions() {
        return \array_merge([new ChaCha20Poly1305()], AesGcm::create(), Aes::create());
    }

    /**
     * @param Encryption|Decryption $cipher
     */
    private static function ivSize($cipher): int {
        return $cipher instanceof AeadCipher ? $cipher->getIvSize() : $cipher->getBlockSize();
    }

    public static function supportedMacs() {
        return [
            new Hash('sha256', 'hmac-sha2-256', 32),
            new Hash('sha1', 'hmac-sha1', 20),
        ];
    }
}
