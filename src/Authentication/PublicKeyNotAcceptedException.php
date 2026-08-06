<?php declare(strict_types=1);

namespace Amp\Ssh\Authentication;

/**
 * The server will not accept this key, whatever we sign with it.
 *
 * Public key authentication asks before it signs: the key is offered on its
 * own, and only a server that would accept it asks for a signature. Failing at
 * that first step means the key is not in authorized_keys for this user, or its
 * algorithm is not one the server permits - and no amount of retrying will
 * change either.
 *
 * It extends AuthenticationFailureException, so code that catches the general
 * failure keeps working; catch this one to tell "wrong key" apart from "the
 * signature did not hold up", which is the same exception and a very different
 * problem.
 */
class PublicKeyNotAcceptedException extends AuthenticationFailureException {
}
