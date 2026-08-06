<?php declare(strict_types=1);

namespace Amp\Ssh\Internal;

/**
 * The signal names RFC 4254 puts on the wire, and the numbers they carry.
 *
 * SSH names signals rather than numbering them, so this exists only to
 * translate at the edges: a number a caller handed to signal(), and a name a
 * server reported a command as having died from.
 *
 * ext-pcntl is not a requirement of this package and does not exist on Windows
 * at all, so its SIG* constants cannot be named here. Naming them made both
 * signal messages fatal wherever the extension is missing - including on the
 * decode path, where a command killed by a signal took the whole connection
 * down rather than one channel. They are still preferred when present, since a
 * platform whose numbering differs - SIGUSR1 is 10 on Linux and 30 on macOS -
 * knows its own better than a fixed table does.
 *
 * @internal
 */
final class Signals {
    /** Linux numbering, used for any name the running platform cannot resolve. */
    private const DEFAULT_NUMBERS = [
        'ABRT' => 6,
        'ALRM' => 14,
        'FPE' => 8,
        'HUP' => 1,
        'ILL' => 4,
        'INT' => 2,
        'KILL' => 9,
        'PIPE' => 13,
        'QUIT' => 3,
        'SEGV' => 11,
        'TERM' => 15,
        'USR1' => 10,
        'USR2' => 12,
    ];

    /** @var array<string, int>|null */
    private static ?array $numbers = null;

    /** @var array<int, string>|null */
    private static ?array $names = null;

    /**
     * The wire name for a signal number, or null if RFC 4254 has none for it.
     */
    public static function name(int $number): ?string {
        self::load();

        return self::$names[$number] ?? null;
    }

    /**
     * The local number for a wire name, or null if it is not one of the names.
     */
    public static function number(string $name): ?int {
        self::load();

        return self::$numbers[$name] ?? null;
    }

    /**
     * Every name that can travel on the wire, for error messages.
     *
     * @return array<int, string>
     */
    public static function names(): array {
        return \array_keys(self::DEFAULT_NUMBERS);
    }

    private static function load(): void {
        if (self::$numbers !== null) {
            return;
        }

        $numbers = [];
        $names = [];

        foreach (self::DEFAULT_NUMBERS as $name => $number) {
            $constant = 'SIG' . $name;
            $resolved = \defined($constant) ? (int) \constant($constant) : $number;

            $numbers[$name] = $resolved;
            $names[$resolved] = $name;
        }

        self::$numbers = $numbers;
        self::$names = $names;
    }
}
