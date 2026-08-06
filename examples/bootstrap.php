<?php declare(strict_types=1);

// Connection details shared by every example in this directory.
//
// They are read from the environment, so that no example has to be edited
// before it runs and no credential is ever written into a file:
//
//   SSH_HOST    host to connect to                (default 127.0.0.1)
//   SSH_PORT    port                              (default 22)
//   SSH_USER    remote user name                  (default: the local user name)
//   SSH_KEY     private key file                  (default: ~/.ssh/id_ed25519, then ~/.ssh/id_rsa)
//   SSH_HOSTS   comma separated list of hosts     (concurrent-hosts.php only)
//   SSH_PASSWORD, SSH_AUTH_METHOD                 (authentication.php only)
//
// For example:
//
//   SSH_HOST=example.com SSH_USER=deploy php examples/multiple-commands.php

require_once __DIR__ . '/../vendor/autoload.php';

$sshDirectory = \rtrim(\getenv('HOME') ?: \getenv('USERPROFILE') ?: '.', '/\\') . '/.ssh';

$host = \getenv('SSH_HOST') ?: '127.0.0.1';
$port = (int) (\getenv('SSH_PORT') ?: '22');

$target = \sprintf('%s:%d', $host, $port);
$username = \getenv('SSH_USER') ?: \get_current_user();

// Prefer the key ssh-keygen writes today, and fall back to the older default.
$keyPath = \getenv('SSH_KEY') ?: (\is_file($sshDirectory . '/id_ed25519')
    ? $sshDirectory . '/id_ed25519'
    : $sshDirectory . '/id_rsa');
