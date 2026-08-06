# Examples

Every example reads its connection details from the environment, so none of them has to be edited
before it runs and no credential is ever written into a file. `bootstrap.php` documents the
variables; the short version is:

```bash
SSH_HOST=example.com SSH_USER=deploy php examples/process.php
```

| | |
|---|---|
| [`process.php`](./process.php) | Run one command, stream its output, read its exit status. |
| [`shell.php`](./shell.php) | The smallest interactive shell that works. |
| [`concurrent-hosts.php`](./concurrent-hosts.php) | One command on many hosts at once, with a cap on open connections and per-host error isolation. |
| [`timeouts.php`](./timeouts.php) | Why cancelling a wait does not stop the command, and what does. |
| [`multiple-commands.php`](./multiple-commands.php) | Many commands over one connection, sequentially and concurrently. |
| [`streaming-output.php`](./streaming-output.php) | Consuming output as it arrives instead of buffering it, and stopping early. |
| [`host-key-verification.php`](./host-key-verification.php) | Learning a host key, pinning it, and watching a mismatch be refused. |
| [`authentication.php`](./authentication.php) | Key, password, certificate and ssh-agent side by side. |
| [`stdin-piping.php`](./stdin-piping.php) | Sending data to a remote command, and the `end()` call that everyone forgets. |
| [`error-handling.php`](./error-handling.php) | Which exception each kind of failure throws, and why a non-zero exit is not one. |
| [`pty-shell.php`](./pty-shell.php) | An interactive shell with the right terminal size, `TERM`, raw mode and resize handling. |
| [`env-and-cwd.php`](./env-and-cwd.php) | Working directory and environment variables, including the `AcceptEnv` refusal. |
| [`tunnel.php`](./tunnel.php) | Reaching something only the server can reach, through a socket that happens to be an SSH channel. |

If you are new to the library, read them in that order: the first two show the shape of the API,
and the rest each answer one question that comes up as soon as it is used for real work.
