<?php declare(strict_types=1);

namespace Amp\Ssh\HostKey;

/**
 * Thrown when a server's host key cannot be trusted.
 *
 * Covers both halves of the check: a signature that does not hold up, and a
 * key that holds up but is not the one known for this host.
 */
class HostKeyVerificationException extends \RuntimeException {
}
