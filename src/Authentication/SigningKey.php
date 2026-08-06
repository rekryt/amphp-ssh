<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

/**
 * A private key that can answer a publickey authentication request.
 *
 * Each key type differs in three ways only: the algorithm name it advertises,
 * the public blob it sends, and how it signs. Everything else about the
 * exchange is identical, which is why the flow lives in PublicKey and the
 * differences live here.
 *
 * @internal
 */
interface SigningKey {
    /**
     * The signature algorithm to advertise.
     *
     * @param string[] $serverSignatureAlgorithms From SSH_MSG_EXT_INFO; empty
     *                                            when the server sent none,
     *                                            which means it predates
     *                                            RFC 8308.
     *
     * @throws AuthenticationFailureException When nothing is acceptable to both sides.
     */
    public function getSignatureAlgorithm(array $serverSignatureAlgorithms): string;

    /**
     * The name that goes inside the signature blob.
     *
     * Usually the same as the advertised algorithm, but a certificate
     * advertises itself while the signature is still made - and named - with
     * the plain key it certifies.
     */
    public function getSignatureFormat(string $algorithm): string;

    /** The public key blob, in its on-the-wire encoding. */
    public function getPublicKeyBlob(): string;

    /**
     * @return string The signature itself, without the algorithm name in front.
     */
    public function sign(string $data, string $algorithm): string;
}
