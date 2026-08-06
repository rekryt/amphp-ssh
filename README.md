# Amp SSH

![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

`amphp/ssh` is an asynchronous SSH-2 client for [Amp](https://github.com/amphp/amp), implemented
from scratch: it speaks the wire protocol directly rather than wrapping libssh2.

## Installation

```bash
composer require amphp/ssh
```

## Requirements

- PHP 8.1+
- [ext-sodium](https://www.php.net/manual/en/book.sodium.php), bundled with PHP since 7.2
- ext-openssl

## Usage

There is no event loop callback to nest inside: with AMPHP v3 the code reads top to bottom and
suspends where it waits.

```php
<?php declare(strict_types=1);

use Amp\ByteStream;
use Amp\Ssh\Authentication\UsernamePassword;
use Amp\Ssh\Process;
use function Amp\Ssh\connect;

$ssh = connect('example.com:22', new UsernamePassword('user', 'secret'));

$process = new Process($ssh, 'ls -la');
$process->start();

$output = ByteStream\buffer($process->getStdout());
$exitCode = $process->join();

$ssh->close();
```

Public key authentication takes an RSA key in PEM form or an Ed25519 key in the OpenSSH format
`ssh-keygen` writes by default:

```php
use Amp\Ssh\Authentication\PublicKey;

$ssh = connect('example.com:22', new PublicKey('user', '/home/user/.ssh/id_ed25519'));
```

Cancelling a wait detaches the caller and nothing else — the remote process keeps running and a
later `join()` still sees its result:

```php
use Amp\TimeoutCancellation;

try {
    $exitCode = $process->join(new TimeoutCancellation(5));
} catch (Amp\CancelledException) {
    $process->kill();
}
```

The [`examples`](./examples) directory covers the rest: running one command on many hosts at once,
reusing a connection, streaming large output, piping data into a remote command, host key pinning,
every authentication method, and which exception each kind of failure throws.

### Tunnels

`createTunnel()` asks the server to connect somewhere and hands back the other end of that
connection. The address is resolved and dialled by the server, so it reaches whatever the server
can reach — a database on a private network, a port bound to the server's own loopback:

```php
$tunnel = $ssh->createTunnel('db.internal', 5432);

$tunnel->write($query);
$response = $tunnel->read();

$tunnel->close();
```

The result is an [`Amp\Socket\Socket`](https://github.com/amphp/socket), so anything that takes a
socket can be pointed through it without knowing SSH is involved. Tunnels are ordinary channels:
open as many as the server's `MaxSessions` allows, alongside commands, on the one connection, and
closing one closes only that one.

TLS is the exception. PHP sets it up in the stream layer, on a socket resource, and a tunnel is a
channel inside the SSH connection rather than a socket of its own — `isTlsConfigurationAvailable()`
returns `false` and `setupTls()` throws. The hop between you and the server is encrypted by SSH
either way; what is not available is TLS running from here to the far end.

A connection the server could not make arrives as a `ChannelException` carrying the reason the
server gave for it.

### Host key verification

`connect()` checks the server against `~/.ssh/known_hosts` by default and refuses to continue if
the host is unknown or its key has changed. Point it at another file, or accept anything, only
where the channel is already trusted:

```php
use Amp\Ssh\HostKey\AcceptAnyHostKey;
use Amp\Ssh\HostKey\KnownHosts;

connect($uri, $auth, hostKeyVerifier: new KnownHosts('/etc/ssh/ssh_known_hosts'));
connect($uri, $auth, hostKeyVerifier: new AcceptAnyHostKey()); // no protection against interception
```

## Supported algorithms

| | |
|---|---|
| Key exchange | curve25519-sha256@libssh.org, diffie-hellman-group18-sha512, diffie-hellman-group16-sha512, diffie-hellman-group14-sha256, diffie-hellman-group14-sha1 |
| Host keys | ssh-ed25519, ecdsa-sha2-nistp521/384/256, rsa-sha2-512, rsa-sha2-256, ssh-rsa, and the `-cert-v01@openssh.com` certificate variant of each, offered ahead of the plain one |
| Ciphers | chacha20-poly1305@openssh.com, aes256/128-gcm@openssh.com, aes256/192/128-ctr, aes256/192/128-cbc |
| MAC | hmac-sha2-256, hmac-sha1 (implicit for the AEAD ciphers) |
| User authentication | password, publickey (RSA, ECDSA, Ed25519), user certificates, ssh-agent |

Every list above is a preference order: the first name the server also offers wins. `ssh-dss` is
not offered at all — its signature cannot be verified here, and advertising a host key algorithm
that would be accepted on the server's word alone is worse than not having it.

Host certificates are trusted through `@cert-authority` lines in `known_hosts`, the same way
OpenSSH does it. The certificate's own signature, its validity window, its type and its
principals are all checked.

### User certificates

A certificate beside the private key, named the way `ssh-keygen` names it, is picked up on its
own; pass a path to use one from somewhere else:

```php
use Amp\Ssh\Authentication\PublicKey;

// Uses /home/user/.ssh/id_ed25519-cert.pub if it exists.
new PublicKey('user', '/home/user/.ssh/id_ed25519');

new PublicKey('user', '/home/user/.ssh/id_ed25519', '', '/etc/ssh/user-cert.pub');
```

### ssh-agent, and keys on a hardware token

Keys on a FIDO security key (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`)
cannot be used directly: the private half never leaves the device, and PHP has no way to talk to
one. Nor can an encrypted key file be opened here. Both work through an agent, which does the
signing itself:

```php
use Amp\Ssh\Authentication\AgentAuthentication;

connect($uri, new AgentAuthentication('user'));            // any key the agent holds
connect($uri, new AgentAuthentication('user', 'me@laptop')); // the one with this comment
```

Every identity is offered in turn, as OpenSSH does, and only the one the server accepts is
actually signed - so a security key is not touched until it is the one being used.

Not implemented: reading `sk-*` or encrypted key files directly (use an agent).

## Versioning

`amphp/ssh` follows [semver](https://semver.org/) like all other `amphp` packages.

**2.0 is a rewrite for AMPHP v3 and is not source compatible with 1.x.** The whole API returns
values directly instead of promises.

Upgrading from 1.x: [`MIGRATION.md`](./MIGRATION.md) walks through it with before-and-after
examples, and covers the changes that compile either way — host keys are verified now, writing to
a finished stdin throws, and cancelling a `join()` no longer stops the remote process.

## Testing

Unit tests need nothing but PHP:

```bash
composer test
```

The integration tests need an SSH server and are skipped unless one is configured:

```bash
docker build -f docker/legacy.Dockerfile -t amphp-ssh-legacy .
docker run -d -p 2222:22 amphp-ssh-legacy

SSH_LOCAL_HOST=127.0.0.1 SSH_LOCAL_PORT=2222 composer test
```

## License

The MIT License (MIT). Please see [`LICENSE`](./LICENSE) for more information.

## Credits

Besides the authors named in `composer.json`, this library carries work from:

 * [Max Furtuna](https://github.com/Ekstazi) — the diffie-hellman-group14, group16 and group18
   key exchanges, window size changes, the dispatcher's error handling, and much of the test
   suite the current one grew out of
 * [Niklas Keller](https://github.com/kelunik) — an infinite loop out of `connect()`, and an
   identification parser strict about the prefix it accepts

And none of it would have been possible without the people who implemented this specification in
PHP first:

 * [PHPSeclib](https://github.com/phpseclib/phpseclib)
 * [PHP Encrypted Streams](https://github.com/jeskew/php-encrypted-streams)
