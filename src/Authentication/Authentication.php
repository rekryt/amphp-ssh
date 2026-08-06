<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

use Amp\Cancellation;
use Amp\Ssh\Transport\BinaryPacketHandler;

interface Authentication {
    /**
     * Authenticate the connection, throwing if the server rejects it.
     *
     * Runs while the connection is not usable by anything else yet, so a
     * failure here — cancellation included — means the caller closes the
     * connection instead of retrying on the same handler.
     *
     * @throws AuthenticationFailureException
     */
    public function authenticate(
        BinaryPacketHandler $handler,
        string $sessionId,
        ?Cancellation $cancellation = null
    ): void;
}
