<?php declare(strict_types=1);

// Every way of proving who you are, side by side.
//
// Pick one with SSH_AUTH_METHOD:
//
//   key          a private key file                             (the default)
//   password     a password, read from SSH_PASSWORD
//   certificate  a key plus the certificate an authority signed
//   agent        whatever a running ssh-agent is holding
//
// Two limits are worth knowing before choosing:
//
//   - A passphrase only opens the older PEM key files, which OpenSSL can
//     decrypt. The "openssh-key-v1" container that ssh-keygen writes today is
//     refused when it is encrypted, with a message saying so.
//   - A key on a hardware token (sk-ssh-ed25519@openssh.com and friends) can
//     never be used directly. The file holds a credential handle, not a
//     private key, and the signing happens on the device.
//
// Both cases are what the agent is for: it already holds the decrypted key, or
// it can talk to the token.

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\Ssh\Authentication\AgentAuthentication;
use Amp\Ssh\Authentication\AuthenticationFailureException;
use Amp\Ssh\Authentication\PublicKey;
use Amp\Ssh\Authentication\UsernamePassword;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;

$method = \getenv('SSH_AUTH_METHOD') ?: 'key';

$authentication = match ($method) {
    // The key file is read directly. The third argument is a passphrase for a
    // PEM key; leave it empty for the unencrypted keys this can open.
    'key' => new PublicKey($username, $keyPath),

    // Passwords are frequently disabled on the server (PasswordAuthentication
    // no), in which case this fails no matter what you send.
    'password' => new UsernamePassword($username, \getenv('SSH_PASSWORD') ?: ''),

    // A certificate is picked up on its own when it sits beside the key under
    // the name ssh-keygen gives it, so this is the same call as 'key' above.
    // Pass a fourth argument to use one from somewhere else:
    //
    //     new PublicKey($username, $keyPath, '', '/etc/ssh/user-cert.pub')
    //
    // Two algorithm names are in play with a certificate: the request
    // advertises the certificate, while the signature is made with the plain
    // key inside it. The library handles that; it is only visible in a packet
    // capture.
    'certificate' => new PublicKey($username, $keyPath),

    // Identities are offered one at a time and only the accepted one is
    // signed, so a security key is not touched until it is the one in use.
    // The second argument narrows the choice to one identity by its comment,
    // which is usually the file name the key was loaded from.
    'agent' => new AgentAuthentication($username, \getenv('SSH_AGENT_COMMENT') ?: null),

    default => throw new \InvalidArgumentException('Unknown SSH_AUTH_METHOD: ' . $method),
};

\printf('Authenticating as %s with the %s method.%s', $username, $method, PHP_EOL);

try {
    $ssh = connect($target, $authentication);
} catch (AuthenticationFailureException $exception) {
    // The server does not say why it refused - that is deliberate on its part,
    // and it means the message here can only report that it did.
    echo 'Rejected: ', $exception->getMessage(), PHP_EOL;

    exit(1);
}

$process = new Process($ssh, 'id');
$process->start();

echo ByteStream\buffer($process->getStdout());
$process->join();

$ssh->close();
