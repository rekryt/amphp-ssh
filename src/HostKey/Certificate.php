<?php declare(strict_types=1);

namespace Amp\Ssh\HostKey;

use Amp\Ssh\Internal\Ecdsa;
use function Amp\Ssh\Transport\read_string;
use function Amp\Ssh\Transport\read_uint32;
use function Amp\Ssh\Transport\read_uint64;

/**
 * An OpenSSH host certificate (PROTOCOL.certkeys).
 *
 * A certificate replaces the host key in the key exchange: the server signs
 * the exchange with the key inside it, and a certificate authority has in turn
 * signed the certificate. That buys a way to trust a host without having ever
 * seen it, at the cost of three extra checks - the CA's signature, the
 * validity window, and whether the name we dialled is among the principals.
 *
 * @internal
 */
final class Certificate {
    public const HOST = 2;

    private const USER = 1;

    /**
     * Certificate algorithm name to the plain algorithm it stands in for.
     *
     * The order is a preference order and deliberately mirrors the one used
     * for plain host keys, so that adding a certificate to a host does not
     * quietly change which algorithm gets negotiated.
     */
    private const ALGORITHMS = [
        'ssh-ed25519-cert-v01@openssh.com' => 'ssh-ed25519',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com' => 'ecdsa-sha2-nistp521',
        'ecdsa-sha2-nistp384-cert-v01@openssh.com' => 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp256-cert-v01@openssh.com' => 'ecdsa-sha2-nistp256',
        'rsa-sha2-512-cert-v01@openssh.com' => 'rsa-sha2-512',
        'rsa-sha2-256-cert-v01@openssh.com' => 'rsa-sha2-256',
        'ssh-rsa-cert-v01@openssh.com' => 'ssh-rsa',
    ];

    private string $algorithm;

    private string $publicKey;

    private int $type;

    private string $keyId;

    /** @var string[] */
    private array $principals;

    private int $validAfter;

    private int $validBefore;

    private string $signatureKey;

    private string $signature;

    private string $signedBody;

    private function __construct() {
    }

    public static function isCertificateAlgorithm(string $algorithm): bool {
        return isset(self::ALGORITHMS[$algorithm]);
    }

    /**
     * @return string[] Certificate algorithm names, in the same preference
     *                  order as the plain algorithms they stand for.
     */
    public static function algorithms(): array {
        return \array_keys(self::ALGORITHMS);
    }

    /** The plain host key algorithm a certificate algorithm carries. */
    public static function underlyingAlgorithm(string $algorithm): string {
        return self::ALGORITHMS[$algorithm];
    }

    /**
     * @throws HostKeyVerificationException On anything malformed.
     */
    public static function parse(string $blob): self {
        try {
            return self::doParse($blob);
        } catch (\RuntimeException $exception) {
            throw new HostKeyVerificationException(
                'Malformed host certificate: ' . $exception->getMessage(),
                0,
                $exception
            );
        }
    }

    private static function doParse(string $blob): self {
        $certificate = new self();
        $payload = $blob;

        $certificate->algorithm = read_string($payload);

        if (!isset(self::ALGORITHMS[$certificate->algorithm])) {
            throw new \RuntimeException('unknown certificate type ' . $certificate->algorithm);
        }

        read_string($payload); // nonce

        // The key fields sit inline and differ per algorithm, so the public key
        // has to be reassembled in the plain format the signature check wants.
        $certificate->publicKey = self::readPublicKey($certificate->algorithm, $payload);

        read_uint64($payload); // serial
        $certificate->type = read_uint32($payload);
        $certificate->keyId = read_string($payload);
        $certificate->principals = self::readPrincipals(read_string($payload));
        $certificate->validAfter = read_uint64($payload);
        $certificate->validBefore = read_uint64($payload);
        read_string($payload); // critical options
        read_string($payload); // extensions
        read_string($payload); // reserved
        $certificate->signatureKey = read_string($payload);

        // Everything up to and including the CA's public key is what the CA
        // signed; what is left is the signature itself.
        $certificate->signedBody = \substr($blob, 0, \strlen($blob) - \strlen($payload));
        $certificate->signature = read_string($payload);

        return $certificate;
    }

    /**
     * Rebuilds the plain public key blob from the fields inlined in the
     * certificate.
     */
    private static function readPublicKey(string $algorithm, string &$payload): string {
        $plain = self::ALGORITHMS[$algorithm];

        if ($plain === 'ssh-ed25519') {
            $key = read_string($payload);

            return \pack('Na*', \strlen($plain), $plain) . \pack('Na*', \strlen($key), $key);
        }

        if (Ecdsa::curveFor($plain) !== null) {
            $curve = read_string($payload);
            $point = read_string($payload);

            return Ecdsa::publicKeyBlob($curve, $point);
        }

        // RSA, whichever signature algorithm the certificate is named after.
        $e = read_string($payload);
        $n = read_string($payload);

        return \pack('Na*', \strlen('ssh-rsa'), 'ssh-rsa')
            . \pack('Na*', \strlen($e), $e)
            . \pack('Na*', \strlen($n), $n);
    }

    /**
     * @return string[]
     */
    private static function readPrincipals(string $blob): array {
        $principals = [];

        while ($blob !== '') {
            $principals[] = read_string($blob);
        }

        return $principals;
    }

    /**
     * Checks everything about the certificate except who signed it.
     *
     * @param callable(string):bool $isTrustedAuthority Decides whether the CA
     *                                                  key is one we accept.
     *
     * @throws HostKeyVerificationException
     */
    public function validate(string $host, callable $isTrustedAuthority, ?int $now = null): void {
        $now ??= \time();

        if ($this->type !== self::HOST) {
            throw new HostKeyVerificationException(\sprintf(
                'The server presented a %s certificate where a host certificate was required.',
                $this->type === self::USER ? 'user' : 'type ' . $this->type
            ));
        }

        if ($now < $this->validAfter) {
            throw new HostKeyVerificationException(\sprintf(
                'The host certificate is not valid until %s.',
                \gmdate('Y-m-d H:i:s', $this->validAfter)
            ));
        }

        if ($now >= $this->validBefore) {
            throw new HostKeyVerificationException(\sprintf(
                'The host certificate expired at %s.',
                \gmdate('Y-m-d H:i:s', $this->validBefore)
            ));
        }

        // An empty principal list means the certificate is good for any host,
        // which OpenSSH allows and which is worth not silently widening.
        if ($this->principals !== [] && !self::matchesPrincipal($this->principals, $host)) {
            throw new HostKeyVerificationException(\sprintf(
                'The host certificate is issued for %s, not for %s.',
                \implode(', ', $this->principals),
                $host
            ));
        }

        if (!$isTrustedAuthority($this->signatureKey)) {
            throw new HostKeyVerificationException(\sprintf(
                'The host certificate for %s is signed by a certificate authority that is not trusted here. '
                    . 'Add it to known_hosts with an @cert-authority line.',
                $host
            ));
        }

        $signature = $this->signature;
        $signatureFormat = read_string($signature);
        $signatureBlob = read_string($signature);

        HostKeySignature::verify($this->signatureKey, $signatureBlob, $signatureFormat, $this->signedBody);
    }

    /**
     * The host key the server actually signed the exchange with.
     */
    public function getPublicKey(): string {
        return $this->publicKey;
    }

    public function getKeyId(): string {
        return $this->keyId;
    }

    /**
     * @return string[]
     */
    public function getPrincipals(): array {
        return $this->principals;
    }

    public function getAuthorityKey(): string {
        return $this->signatureKey;
    }

    /**
     * @param string[] $principals
     */
    private static function matchesPrincipal(array $principals, string $host): bool {
        foreach ($principals as $principal) {
            if (\strcasecmp($principal, $host) === 0) {
                return true;
            }

            // OpenSSH allows patterns in principals.
            if (\strcspn($principal, '*?') !== \strlen($principal) && \fnmatch($principal, $host, FNM_CASEFOLD)) {
                return true;
            }
        }

        return false;
    }
}
