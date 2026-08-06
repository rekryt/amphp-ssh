# Upgrading from 1.x to 2.0

> Two version numbers are in play and they are easy to mix up: **this package** goes from 1.x to
> 2.0, because **AMPHP** goes from v2 to v3. Everywhere below, "1.x" and "2.0" mean `amphp/ssh`.

2.0 is a rewrite on top of AMPHP v3. The protocol work is unchanged, but every asynchronous
boundary moved: promises are gone, and so is the callback you used to nest everything inside.

Most upgrades are mechanical — delete `yield`, delete the `Loop::run()` wrapper — and the compiler
finds what you missed, because the return types changed. The parts that do *not* announce
themselves are collected under [Behaviour that changed silently](#behaviour-that-changed-silently);
read that section even if everything else compiles.

## Requirements

| | 1.x | 2.0 |
|---|---|---|
| PHP | 7.0+ | 8.1+ |
| amphp/amp | ^2.0 | ^3.1 |
| Extensions | ext-sodium | ext-sodium, ext-openssl |

`ext-openssl` was always needed for AES and RSA; 2.0 just says so.

## The shape of the change

There is no event loop callback any more. Code reads top to bottom and suspends where it waits.

```php
// 1.x
Amp\Loop::run(function () {
    $ssh = yield Amp\Ssh\connect('example.com:22', $auth);
    $process = new Amp\Ssh\Process($ssh, 'ls -la');

    yield $process->start();
    $exitCode = yield $process->join();

    yield $ssh->close();
});

// 2.0
$ssh = Amp\Ssh\connect('example.com:22', $auth);
$process = new Amp\Ssh\Process($ssh, 'ls -la');

$process->start();
$exitCode = $process->join();

$ssh->close();
```

If you need concurrency, that is now an explicit `Amp\async()` rather than a side effect of not
yielding:

```php
// 1.x - three processes, started concurrently by not yielding
$promises = [];
foreach ($commands as $command) {
    $process = new Process($ssh, $command);
    yield $process->start();
    $promises[] = $process->join();
}
$codes = yield Amp\Promise\all($promises);

// 2.0
$futures = [];
foreach ($commands as $command) {
    $process = new Process($ssh, $command);
    $process->start();
    $futures[] = Amp\async(fn () => $process->join());
}
$codes = Amp\Future\await($futures);
```

## Signatures

| 1.x | 2.0 |
|---|---|
| `connect(): Promise` | `connect(): SshResource` |
| `Process::start(): Promise` | `Process::start(): void` |
| `Process::join(): Promise` | `Process::join(?Cancellation): int\|false` |
| `Process::signal(int): Promise` | `Process::signal(int): void` |
| `Process::kill(): void` | `Process::kill(): void` |
| `Process::getStdin(): OutputStream` | `Process::getStdin(): WritableStream` |
| `Process::getStdout(): InputStream` | `Process::getStdout(): ReadableStream` |
| `Shell::start(): Promise` | `Shell::start(): void` |
| `Shell::changeWindowSize(): Promise` | `Shell::changeWindowSize(): void` |
| `SshResource::close(): Promise` | `SshResource::close(): void` |
| `Session::getDataEmitter(): Emitter` | `Session::getDataIterator(): ConcurrentIterator` |
| `Session::getDataExtendedEmitter()` | `Session::getDataExtendedIterator()` |
| `Session::getRequestEmitter()` | `Session::getRequestIterator()` |

`connect()` also gained three optional parameters after `$identification`: a `Cancellation`, a
`ConnectContext`, and a `HostKeyVerifier`. Pass them by name.

## Reading and writing

Streams follow `amphp/byte-stream` 2.x. Reading is a call rather than a promise, and the helpers
are usually shorter than the loop they replace:

```php
// 1.x
$output = '';
while (null !== $chunk = yield $process->getStdout()->read()) {
    $output .= $chunk;
}

// 2.0
$output = Amp\ByteStream\buffer($process->getStdout());

// or, still explicit
$output = '';
while (null !== $chunk = $process->getStdout()->read()) {
    $output .= $chunk;
}
```

Writing changed in one detail worth knowing: `end()` no longer takes data.

```php
// 1.x
yield $process->getStdin()->end("last chunk\n");

// 2.0
$process->getStdin()->write("last chunk\n");
$process->getStdin()->end();
```

Piping needs a fiber if you want it to run alongside something else, and you should wait for it
before closing the connection — otherwise output still sitting in the channel buffers is lost:

```php
// 1.x
\Amp\ByteStream\pipe($process->getStdout(), new ResourceOutputStream(STDOUT));
yield $process->join();

// 2.0
$piping = Amp\async(fn () => Amp\ByteStream\pipe($process->getStdout(), Amp\ByteStream\getStdout()));
$exitCode = $process->join();
$piping->await();
```

## Channels, if you used them directly

`Emitter` and `Iterator` became `Queue` and `ConcurrentIterator` from `amphp/pipeline`.

```php
// 1.x
$iterator = $session->getDataEmitter()->iterate();
while (yield $iterator->advance()) {
    $message = $iterator->getCurrent();
}

// 2.0
$iterator = $session->getDataIterator();
while ($iterator->continue()) {
    $message = $iterator->getValue();
}
```

Two rules come with the new type, and breaking either produces confusing failures rather than
errors at the point of the mistake:

- **Take the iterator once and keep it.** `getDataIterator()` hands back the same instance every
  time, but a `Queue::iterate()` of your own would create a new one — and an iterator being
  garbage collected disposes the queue for everyone still using it.
- **Do not `break` out of the loop while the channel is alive.** Abandoning the iterator has the
  same effect. Read to the end, or close the channel first.

## Behaviour that changed silently

These compile either way. They are the ones to look for.

### Host keys are verified

1.x checked nothing at all, so any server was accepted. 2.0 checks `~/.ssh/known_hosts` and
refuses an unknown host or a changed key.

If you connect to hosts that are not in `known_hosts` — disposable containers, machines rebuilt
from an image — say so explicitly:

```php
use Amp\Ssh\HostKey\AcceptAnyHostKey;
use Amp\Ssh\HostKey\KnownHosts;

// Trust a specific file instead of the default.
connect($uri, $auth, hostKeyVerifier: new KnownHosts('/etc/ssh/ssh_known_hosts'));

// Accept anything. This is what 1.x did, and it offers no protection against
// an intercepted connection.
connect($uri, $auth, hostKeyVerifier: new AcceptAnyHostKey());
```

`new KnownHosts($path, rejectUnknown: false)` is the middle ground: an unknown host passes, a
changed key still does not.

### Writing to a finished stdin throws

1.x silently discarded the write. 2.0 throws `Amp\ByteStream\ClosedException`, which is usually
how you find out something was wrong all along.

```php
// 2.0 - if the remote process may have exited already
if ($process->getStdin()->isWritable()) {
    $process->getStdin()->write($data);
}
```

### Cancelling a join does not kill the process

Cancellation detaches the caller and nothing else. The remote process keeps running, the channel
stays open, and a later `join()` returns the same result.

```php
try {
    $exitCode = $process->join(new Amp\TimeoutCancellation(5));
} catch (Amp\CancelledException) {
    $process->kill();       // if that is what you want
    $exitCode = $process->join();
}
```

### A peer that is not an SSH server is no longer an authentication failure

1.x reported a peer that hung up before sending its identification string as an
`AuthenticationFailureException`, which is where it sends you to look: at credentials that were
never offered, in an exchange that never reached authentication. 2.0 throws
`Amp\Ssh\Transport\ServerIdentificationException` instead.

```php
use Amp\Ssh\Transport\ServerIdentificationException;

try {
    $ssh = connect($uri, $auth);
} catch (ServerIdentificationException) {
    // Wrong port, a firewall answering for sshd, or a web server on 22.
} catch (Amp\Ssh\Authentication\AuthenticationFailureException) {
    // It is sshd, and it turned you away.
}
```

If you catch `AuthenticationFailureException` around `connect()` and want the old behaviour,
catch both. Note that neither has a timeout of its own: `connect()` waits for the identification
line as long as the peer keeps the socket open, so pass a `cancellation`.

### Some servers are reachable that were not, and vice versa

2.0 speaks `rsa-sha2-*` and `SSH_MSG_EXT_INFO`, without which OpenSSH 8.8 and newer refuse the
connection outright — so hosts that 1.x could not reach now work. In the other direction,
`ssh-dss` host keys are no longer offered: their signature cannot be verified here, and 1.x
accepted them on the server's word alone.

### kill() no longer needs ext-pcntl, and may still do nothing

1.x named the `SIGKILL` constant and built its whole signal table out of `SIG*` constants, so
`signal()` and `kill()` fataled on any build without the extension — Windows included. They no
longer do.

What has not changed is that the request they send is advisory. OpenSSH's sshd does not act on it,
so if 1.x code relied on `kill()` to stop something, it was relying on nothing. Bound the command
where it runs (`timeout 30 mycommand`), or give it a terminal through `Shell`, where closing the
channel sends `SIGHUP`.

### A connection is good for more than ten commands

1.x addressed every message with its own channel number instead of the peer's, and never answered
a close with a close. Neither shows up on a connection used for one command, which is why they
survived so long. On a connection reused for many, both do: the server holds each session slot
open, and somewhere around the eleventh command — `MaxSessions` in `sshd_config`, ten by default —
channels stop opening. Before that, a channel number the server has reused can drop the whole
connection.

Nothing to change in your code. If you worked around it by reconnecting every few commands, you
no longer have to.

### A working directory that cannot be entered stops the command

`Process`'s `$cwd` was pasted into the command as shell text and joined with `;`. Two consequences,
both fixed: a directory that could not be entered left `cd` to fail and the command to run in the
login directory instead, and anything in the path that a shell finds interesting was acted on.

```php
new Process($ssh, 'rm -rf build', '/srv/app');   // 1.x: cd /srv/app; rm -rf build
                                                 // 2.0: cd '/srv/app' && rm -rf build
```

`$cwd` is now a directory name, quoted and taken literally, so a path from configuration cannot
run commands of its own. **Two things change for existing code:**

- If you were escaping the path yourself, stop — it is escaped again, and `cd "'/srv/app'"` fails.
- Nothing in the path expands any more. `~/app` and `$HOME/app` are directory names now, not your
  home directory. A session already starts there, so leave `$cwd` null instead.

The command itself is unchanged: it is shell text and is not quoted.

## Things worth adopting

None of these are required, but they did not exist in 1.x.

```php
// Authenticate with whatever the agent holds - the only way to use a key on a
// hardware token, or an encrypted key file.
use Amp\Ssh\Authentication\AgentAuthentication;

connect($uri, new AgentAuthentication('user'));

// Ed25519 and ECDSA keys, including the openssh-key-v1 format ssh-keygen writes
// by default. A "<key>-cert.pub" beside the key is picked up on its own.
use Amp\Ssh\Authentication\PublicKey;

connect($uri, new PublicKey('user', '/home/user/.ssh/id_ed25519'));

// Cancellation all the way down.
connect($uri, $auth, cancellation: new Amp\TimeoutCancellation(10));
```

Large transfers are also worth revisiting: 1.x sent each write as a single packet regardless of
the peer's limits and never replenished its receive window, so anything past a megabyte was
unreliable. 2.0 splits writes and paces them against the window.

## Checklist

1. Raise `php` to `>=8.1` and `amphp/ssh` to `^2.0`.
2. Delete every `Loop::run()` wrapper and every `yield` in front of a call into this library.
3. Replace `Amp\Promise\all()` on process joins with `Amp\async()` plus `Amp\Future\await()`.
4. Replace `->end($data)` with `->write($data)` followed by `->end()`.
5. Rename `get*Emitter()->iterate()` to `get*Iterator()`, and `advance()`/`getCurrent()` to
   `continue()`/`getValue()`.
6. Decide what host key policy you want, and pass a verifier if the default is not it.
7. Look for writes to stdin that might race the process exiting.
8. Re-check anything that depended on a cancelled `join()` stopping the process.
