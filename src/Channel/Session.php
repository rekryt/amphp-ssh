<?php declare(strict_types=1);

namespace Amp\Ssh\Channel;

use Amp\Ssh\Message\ChannelOpen;
use Amp\Ssh\Message\ChannelRequestEnv;
use Amp\Ssh\Message\ChannelRequestExec;
use Amp\Ssh\Message\ChannelRequestPty;
use Amp\Ssh\Message\ChannelRequestShell;
use Amp\Ssh\Message\ChannelRequestSignal;
use Amp\Ssh\Message\ChannelRequestWindowChange;

/**
 * @internal
 */
final class Session extends Channel {
    protected function getType(): string {
        return ChannelOpen::TYPE_SESSION;
    }

    public function env(string $name, string $value, bool $quiet = false): bool {
        $request = new ChannelRequestEnv();
        $request->recipientChannel = $this->peerChannelId;
        $request->value = $value;
        $request->name = $name;
        $request->wantReply = !$quiet;

        try {
            return $this->doRequest($request, !$quiet);
        } catch (\Throwable $exception) {
            throw new SessionEnvException(\sprintf('Unable to set env var %s, check if it is authorised on the server', $name), 0, $exception);
        }
    }

    public function signal(int $signo): bool {
        $request = new ChannelRequestSignal();
        $request->recipientChannel = $this->peerChannelId;
        $request->signal = $signo;

        return $this->doRequest($request, false);
    }

    public function pty(int $columns = 80, int $rows = 24, int $width = 800, int $height = 600): bool {
        $request = new ChannelRequestPty();
        $request->recipientChannel = $this->peerChannelId;
        $request->columns = $columns;
        $request->rows = $rows;
        $request->width = $width;
        $request->height = $height;

        return $this->doRequest($request);
    }

    public function changeWindowSize(int $columns = 80, int $rows = 24, int $width = 800, int $height = 600): bool {
        $request = new ChannelRequestWindowChange();
        $request->recipientChannel = $this->peerChannelId;
        $request->columns = $columns;
        $request->rows = $rows;
        $request->width = $width;
        $request->height = $height;

        return $this->doRequest($request, false);
    }

    public function shell(): bool {
        $request = new ChannelRequestShell();
        $request->recipientChannel = $this->peerChannelId;

        return $this->doRequest($request);
    }

    public function exec(string $command): bool {
        $request = new ChannelRequestExec();
        $request->recipientChannel = $this->peerChannelId;
        $request->command = $command;

        return $this->doRequest($request);
    }
}
