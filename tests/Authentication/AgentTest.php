<?php declare(strict_types=1);

namespace Amp\Ssh\Tests\Authentication;

use Amp\ByteStream\ReadableBuffer;
use Amp\ByteStream\WritableBuffer;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Ssh\Authentication\Agent;
use Amp\Ssh\Authentication\AgentKey;
use Amp\Ssh\Authentication\AuthenticationFailureException;

/**
 * The SSH agent protocol, spoken against a scripted agent.
 *
 * Worth testing on its own because this is the only route to a key on a
 * hardware token: the private half never leaves the device, so the signature
 * can only ever come back over this wire.
 */
class AgentTest extends AsyncTestCase {
    private const IDENTITIES_ANSWER = 12;

    private const SIGN_RESPONSE = 14;

    private const FAILURE = 5;

    private static function string(string $value): string {
        return \pack('Na*', \strlen($value), $value);
    }

    private static function framed(string $message): string {
        return \pack('Na*', \strlen($message), $message);
    }

    /**
     * @param array<int, array{0: string, 1: string}> $identities Blob and comment.
     */
    private static function identitiesAnswer(array $identities): string {
        $payload = \chr(self::IDENTITIES_ANSWER) . \pack('N', \count($identities));

        foreach ($identities as [$blob, $comment]) {
            $payload .= self::string($blob) . self::string($comment);
        }

        return self::framed($payload);
    }

    private static function signResponse(string $signatureBlob): string {
        return self::framed(\chr(self::SIGN_RESPONSE) . self::string($signatureBlob));
    }

    private function agent(string $scriptedReplies): array {
        $written = new WritableBuffer();
        $agent = new Agent(new ReadableBuffer($scriptedReplies), $written);

        return [$agent, $written];
    }

    public function testListsIdentities() {
        [$agent] = $this->agent(self::identitiesAnswer([
            [self::string('ssh-ed25519') . self::string(\random_bytes(32)), 'me@laptop'],
            [self::string('ssh-rsa') . self::string("\x01\x00\x01") . self::string(\random_bytes(256)), 'old key'],
        ]));

        $identities = $agent->getIdentities();

        self::assertCount(2, $identities);
        self::assertSame('me@laptop', $identities[0]['comment']);
        self::assertSame('old key', $identities[1]['comment']);
    }

    public function testEmptyAgent() {
        [$agent] = $this->agent(self::identitiesAnswer([]));

        self::assertSame([], $agent->getIdentities());
    }

    /**
     * A reply split across reads must still be assembled: the length prefix
     * and the body often arrive together, and the surplus of one read is the
     * start of the next message.
     */
    public function testRepliesSplitAcrossReadsAreAssembled() {
        $answer = self::identitiesAnswer([[self::string('ssh-ed25519') . self::string(\random_bytes(32)), 'x']]);

        $chunks = \str_split($answer, 3);
        [$agent] = $this->agent(\implode('', $chunks));

        self::assertCount(1, $agent->getIdentities());
    }

    public function testSignRequestIsWellFormed() {
        $blob = self::string('ssh-ed25519') . self::string(\random_bytes(32));
        $signature = self::string('ssh-ed25519') . self::string(\random_bytes(64));

        [$agent, $written] = $this->agent(self::signResponse($signature));

        self::assertSame($signature, $agent->sign($blob, 'data to sign', Agent::FLAG_RSA_SHA2_512));

        // buffer() waits for the stream to be closed before handing anything
        // back, so nothing has been written from its point of view until then.
        $written->end();
        $request = $written->buffer();

        // uint32 length, type 13, then the key, the data and the flags.
        $length = \unpack('N', \substr($request, 0, 4))[1];

        self::assertSame($length, \strlen($request) - 4);
        self::assertSame(13, \ord($request[4]));
        self::assertStringContainsString($blob, $request);
        self::assertStringContainsString('data to sign', $request);
        self::assertSame(Agent::FLAG_RSA_SHA2_512, \unpack('N', \substr($request, -4))[1]);
    }

    /**
     * A refusal is the normal outcome when a security key is unplugged or the
     * touch times out, so it has to be reported as such.
     */
    public function testRefusalToSignIsReported() {
        [$agent] = $this->agent(self::framed(\chr(self::FAILURE)));

        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/refused to sign/');

        $agent->sign('blob', 'data');
    }

    public function testTruncatedReplyIsReported() {
        [$agent] = $this->agent(\pack('N', 64) . 'too short');

        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/closed the connection/');

        $agent->getIdentities();
    }

    public function testAbsurdLengthIsRejected() {
        [$agent] = $this->agent(\pack('N', 0x7FFFFFFF));

        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/implausible length/');

        $agent->getIdentities();
    }

    public function testMissingAgentIsReportedWithInstructions() {
        $this->expectException(AuthenticationFailureException::class);
        $this->expectExceptionMessageMatches('/SSH_AUTH_SOCK/');

        Agent::connect('');
    }

    /**
     * The agent returns a complete signature blob, but the caller wraps the
     * signature again - so the inner one has to be unwrapped, not nested.
     */
    public function testAgentKeyReturnsTheBareSignature() {
        $raw = \random_bytes(64);
        $blob = self::string('ssh-ed25519') . self::string(\random_bytes(32));

        [$agent] = $this->agent(self::signResponse(self::string('ssh-ed25519') . self::string($raw)));

        $key = new AgentKey($agent, $blob, 'me@laptop');

        self::assertSame('ssh-ed25519', $key->getType());
        self::assertSame('me@laptop', $key->getComment());
        self::assertSame($raw, $key->sign('data', 'ssh-ed25519'));
    }

    /**
     * An RSA key can be signed three ways, and the agent only knows which by
     * the flags it is given.
     */
    public function testRsaKeyAsksForTheStrongestAlgorithmTheServerTakes() {
        $blob = self::string('ssh-rsa') . self::string("\x01\x00\x01") . self::string(\random_bytes(256));
        [$agent] = $this->agent(self::identitiesAnswer([]));

        $key = new AgentKey($agent, $blob);

        self::assertSame('rsa-sha2-512', $key->getSignatureAlgorithm(['rsa-sha2-256', 'rsa-sha2-512', 'ssh-rsa']));
        self::assertSame('rsa-sha2-256', $key->getSignatureAlgorithm(['rsa-sha2-256', 'ssh-rsa']));
        self::assertSame('ssh-rsa', $key->getSignatureAlgorithm([]));
    }

    /**
     * A security key is named by its type; there is nothing to negotiate.
     */
    public function testSecurityKeyAlgorithmIsItsType() {
        $blob = self::string('sk-ssh-ed25519@openssh.com')
            . self::string(\random_bytes(32))
            . self::string('ssh:');

        [$agent] = $this->agent(self::identitiesAnswer([]));

        $key = new AgentKey($agent, $blob);

        self::assertSame('sk-ssh-ed25519@openssh.com', $key->getSignatureAlgorithm([]));
        self::assertSame('sk-ssh-ed25519@openssh.com', $key->getType());
    }
}
