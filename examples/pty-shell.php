<?php declare(strict_types=1);

// An interactive shell that behaves like a terminal.
//
// Shell::start() already asks the server for a pseudo terminal, so `top` and
// `vim` will run. Whether they are usable is a different question, and it
// comes down to three things this example adds over the plain shell.php:
//
//   - the real size of your terminal, so full screen programs do not draw at
//     80x24 into a window that is not 80x24;
//   - TERM, so the remote side knows which escape sequences you understand;
//   - local raw mode, so keystrokes reach the server one at a time instead of
//     a line at a time, and are echoed once by the server rather than twice.
//
// SIGWINCH keeps the size correct when the window is resized afterwards.

require_once __DIR__ . '/bootstrap.php';

use function Amp\async;
use Amp\ByteStream;
use Amp\CancelledException;
use Amp\Future;
use Amp\Ssh\Authentication\PublicKey;
use function Amp\Ssh\connect;
use Amp\Ssh\Shell;
use Amp\TimeoutCancellation;
use Revolt\EventLoop;
use Revolt\EventLoop\UnsupportedFeatureException;

/** SIGWINCH, spelled out because the constant needs ext-pcntl. */
const SIGNAL_WINDOW_CHANGE = 28;

$interactive = PHP_OS_FAMILY !== 'Windows' && \stream_isatty(STDIN);

/**
 * The terminal size, falling back to the conventional default.
 *
 * @return array{0: int, 1: int}
 */
function terminalSize(): array {
    $size = PHP_OS_FAMILY === 'Windows' ? null : \shell_exec('stty size 2>/dev/null');

    if ($size !== null && \preg_match('/^(\d+) (\d+)$/', \trim((string) $size), $matches) === 1) {
        return [(int) $matches[2], (int) $matches[1]];
    }

    return [80, 24];
}

$ssh = connect($target, new PublicKey($username, $keyPath));

// The environment is applied without asking for a reply, so a variable the
// server refuses is dropped in silence here. Process does ask, and throws.
// Either way TERM is one of the few names sshd accepts by default.
$shell = new Shell($ssh, ['TERM' => \getenv('TERM') ?: 'xterm-256color']);

[$columns, $rows] = terminalSize();

// The pixel dimensions are advisory and almost everything ignores them; a
// plausible cell size is enough.
$shell->start($columns, $rows, $columns * 8, $rows * 16);

// Save the local terminal settings before changing them, and put it in raw
// mode: no line buffering, no local echo, and Ctrl-C travels to the server
// instead of killing this script.
$savedTerminal = $interactive ? \trim((string) \shell_exec('stty -g')) : '';

if ($interactive) {
    \shell_exec('stty raw -echo');
}

try {
    if ($interactive) {
        try {
            EventLoop::onSignal(SIGNAL_WINDOW_CHANGE, static function () use ($shell): void {
                if (!$shell->isRunning()) {
                    return;
                }

                [$columns, $rows] = terminalSize();
                $shell->changeWindowSize($columns, $rows, $columns * 8, $rows * 16);
            });
        } catch (UnsupportedFeatureException) {
            // Without ext-pcntl the remote side keeps the size it was given.
        }
    }

    $piping = [
        async(static fn () => ByteStream\pipe($shell->getStdout(), ByteStream\getStdout())),
        async(static fn () => ByteStream\pipe($shell->getStderr(), ByteStream\getStderr())),
    ];

    $stdin = ByteStream\getStdin();

    // Unblock the read below when the remote shell exits on its own, e.g.
    // because the user typed `exit`.
    async(static function () use ($shell, $stdin): void {
        $shell->join();
        $stdin->close();
    });

    while ($shell->isRunning()) {
        $read = $stdin->read();

        if ($read === null) {
            break;
        }

        // The shell may have exited while that read was pending; writing to a
        // stream that has ended throws.
        if (!$shell->getStdin()->isWritable()) {
            break;
        }

        $shell->getStdin()->write($read);
    }

    // Whatever the shell printed last is still on its way through those pipes.
    // Closing the connection now would discard it, so wait - but only for a
    // moment, because a shell that is still running never ends them at all.
    try {
        Future\await($piping, new TimeoutCancellation(2));
    } catch (CancelledException) {
        // Still producing output; the connection is going away regardless.
    }
} finally {
    // Leaving the terminal in raw mode would make the shell that started this
    // script unusable, so restore it whatever happened.
    if ($interactive) {
        \shell_exec('stty ' . $savedTerminal);
    }

    $ssh->close();
}
