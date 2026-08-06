<?php declare(strict_types=1);

namespace Amp\Ssh\Transport;

/**
 * @internal
 */
interface BinaryPacketHandler extends BinaryPacketReader, BinaryPacketWriter {
    public function close(): void;
}
