<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Ssh\Internal\Ecdsa;

/**
 * Turns the contents of a private key file into something that can sign.
 *
 * Two container formats are in circulation. The older PEM ones OpenSSL reads
 * directly; the "openssh-key-v1" container it cannot read at all, and that is
 * the only shape an Ed25519 key comes in and the default for everything else
 * that ssh-keygen writes nowadays.
 *
 * @internal
 */
final class PrivateKeyLoader {
    /**
     * @throws AuthenticationFailureException
     */
    public static function load(string $contents, string $passphrase): SigningKey {
        if (OpenSshPrivateKey::looksLikeOne($contents)) {
            return OpenSshPrivateKey::parse($contents);
        }

        $key = \openssl_get_privatekey($contents, $passphrase);

        if ($key === false) {
            throw new AuthenticationFailureException('Cannot get private key (maybe wrong passphrase ?)');
        }

        $details = \openssl_pkey_get_details($key);

        if ($details === false) {
            throw new AuthenticationFailureException('Cannot read the private key details');
        }

        if ($details['type'] === OPENSSL_KEYTYPE_RSA) {
            return new RsaKey($key, $details);
        }

        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            return self::ec($key, $details);
        }

        throw new AuthenticationFailureException('Private Key Format is not supported.');
    }

    private static function ec(\OpenSSLAsymmetricKey $key, array $details): EcdsaKey {
        $curveName = $details['ec']['curve_name'] ?? '';
        $curve = Ecdsa::curveFromOpenSsl($curveName);

        if ($curve === null) {
            throw new AuthenticationFailureException(\sprintf(
                'Unsupported EC curve %s; SSH defines nistp256, nistp384 and nistp521.',
                $curveName ?: 'of unknown name'
            ));
        }

        return new EcdsaKey($key, $curve, Ecdsa::point($curve, $details['ec']['x'], $details['ec']['y']));
    }
}
