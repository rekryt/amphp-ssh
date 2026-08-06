<?php declare(strict_types=1);

// Working directory and environment variables.
//
// Process takes both, and they behave very differently:
//
//   new Process($ssh, $command, $cwd, $env)
//
// $cwd is a directory name and is taken literally. It is quoted for the remote
// shell, so a space or a quote in it is part of the name and a semicolon cannot
// start a command of its own - which matters as soon as the path comes from
// configuration rather than a literal in the source.
//
// The flip side is that nothing in it is expanded: "~" and "$HOME" are
// directory names rather than your home directory. Leave $cwd out to run there,
// which is where a session starts anyway.
//
// It is joined to the command with &&, so a directory that cannot be entered
// stops the command rather than running it in the home directory instead.
//
// The command itself is the opposite: shell text, not quoted, because running
// a shell command is the point of it.
//
// $env is a real SSH request per variable, and the server is free to refuse
// it. sshd does refuse by default: AcceptEnv is usually no wider than
// "LANG LC_*", so anything of your own is rejected and Process reports that by
// throwing. Shell asks for the same thing without waiting for a reply, so
// there the refusal passes unnoticed.

require_once __DIR__ . '/bootstrap.php';

use Amp\ByteStream;
use Amp\Ssh\Authentication\PublicKey;
use Amp\Ssh\Channel\SessionEnvException;
use function Amp\Ssh\connect;
use Amp\Ssh\Process;

$ssh = connect($target, new PublicKey($username, $keyPath));

/**
 * Runs a command and returns its output, for the sake of the examples below.
 */
function run(\Amp\Ssh\SshResource $ssh, string $command, ?string $cwd = null, array $env = []): string {
    $process = new Process($ssh, $command, $cwd, $env);
    $process->start();

    $output = ByteStream\buffer($process->getStdout());
    $process->join();

    return \rtrim($output);
}

echo 'pwd in /tmp:  ', run($ssh, 'pwd', '/tmp'), PHP_EOL;
echo 'pwd in $HOME: ', run($ssh, 'pwd'), PHP_EOL;

// The whole string is one directory name. Nothing after the semicolon runs -
// the shell is looking for a directory called "/tmp; echo pwned", and says so.
$process = new Process($ssh, 'echo this should not print', '/tmp; echo pwned');
$process->start();

$refused = \trim(ByteStream\buffer($process->getStderr()));
$printed = \trim(ByteStream\buffer($process->getStdout()));
$process->join();

echo 'hostile path: ', $refused === '' ? '(no error?)' : $refused, PHP_EOL;
echo '  and it ran: ', $printed === '' ? 'nothing, as it should' : $printed, PHP_EOL;

// LANG is on the list sshd accepts out of the box, so this one usually works.
try {
    echo 'LANG:         ', run($ssh, 'echo "${LANG:-unset}"', null, ['LANG' => 'C.UTF-8']), PHP_EOL;
} catch (SessionEnvException $exception) {
    echo 'LANG refused:  ', $exception->getMessage(), PHP_EOL;
}

// A name of your own almost certainly is not, unless the server was configured
// for it. The failure is explicit rather than the variable silently missing.
try {
    echo 'DEPLOY_ENV:   ', run($ssh, 'echo "${DEPLOY_ENV:-unset}"', null, ['DEPLOY_ENV' => 'production']), PHP_EOL;
} catch (SessionEnvException $exception) {
    echo 'DEPLOY_ENV refused by the server.', PHP_EOL;
    echo '  To allow it, sshd_config needs: AcceptEnv DEPLOY_ENV', PHP_EOL;

    // Until then, put the assignment in the command itself. The remote shell
    // sets it, so no server side configuration is involved - at the cost of
    // having to escape the value.
    $assignment = \sprintf('DEPLOY_ENV=%s', \escapeshellarg('production'));

    echo '  Inline instead: ', run($ssh, $assignment . ' sh -c \'echo "$DEPLOY_ENV"\''), PHP_EOL;
}

// The two combine the way you would expect: cd first, then the command with
// whatever environment the server accepted.
echo PHP_EOL, run($ssh, 'echo "running in $PWD with LANG=$LANG"', '/var/tmp', ['LANG' => 'C.UTF-8']), PHP_EOL;

$ssh->close();
