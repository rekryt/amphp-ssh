<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Ssh\HostKey\Certificate;
use function Amp\Ssh\Transport\read_string;

/**
 * A key the agent holds, signed on our behalf.
 *
 * The private half is never seen here - which is the point for a key on a
 * hardware token, where it does not exist outside the device at all.
 *
 * @internal
 */
final class AgentKey implements SigningKey {
    /** Flags that ask the agent for a SHA-2 signature over an RSA key. */
    private const RSA_FLAGS = [
        'rsa-sha2-512' => Agent::FLAG_RSA_SHA2_512,
        'rsa-sha2-256' => Agent::FLAG_RSA_SHA2_256,
    ];

    private Agent $agent;

    private string $blob;

    private string $type;

    private string $comment;

    public function __construct(Agent $agent, string $blob, string $comment = '') {
        $this->agent = $agent;
        $this->blob = $blob;
        $this->comment = $comment;

        $reader = $blob;
        $this->type = read_string($reader);
    }

    public function getComment(): string {
        return $this->comment;
    }

    public function getType(): string {
        return $this->type;
    }

    public function getSignatureAlgorithm(array $serverSignatureAlgorithms): string {
        // An RSA key can be signed three ways and the agent has to be told
        // which; everything else has exactly one algorithm, named by the key.
        if ($this->type !== 'ssh-rsa') {
            return $this->type;
        }

        if ($serverSignatureAlgorithms === []) {
            return 'ssh-rsa';
        }

        foreach (\array_keys(self::RSA_FLAGS) as $algorithm) {
            if (\in_array($algorithm, $serverSignatureAlgorithms, true)) {
                return $algorithm;
            }
        }

        return 'ssh-rsa';
    }

    public function getSignatureFormat(string $algorithm): string {
        return Certificate::isCertificateAlgorithm($algorithm)
            ? Certificate::underlyingAlgorithm($algorithm)
            : $algorithm;
    }

    public function getPublicKeyBlob(): string {
        return $this->blob;
    }

    public function sign(string $data, string $algorithm): string {
        // The agent hands back a complete signature blob, but the caller wraps
        // the result in one of its own, so the inner signature is unwrapped
        // here rather than double-encoded.
        $blob = $this->agent->sign($this->blob, $data, self::RSA_FLAGS[$algorithm] ?? 0);

        read_string($blob); // signature format, re-added by the caller

        return read_string($blob);
    }
}
