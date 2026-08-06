<?php declare(strict_types=1);

namespace Amp\Ssh\Encryption\CipherMode;

/**
 * @internal
 */
interface CipherMode {
    public function getCurrentIV(): string;

    public function updateIV(string $payload);
}
