<?php declare(strict_types=1);

namespace Amp\Ssh\Tests;

use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\SshResource;

/**
 * Base for tests that need a real sshd.
 *
 * Skips instead of failing when no server is reachable, so a clean checkout
 * still produces a green suite; the unit tests around it cover the logic that
 * does not need a server at all.
 */
abstract class IntegrationTestCase extends AsyncTestCase {
    protected function setUp(): void {
        parent::setUp();

        if (!SshServer::isAvailable()) {
            self::markTestSkipped(SshServer::skipReason());
        }
    }

    protected function getSsh(): SshResource {
        return SshServer::connect();
    }
}
