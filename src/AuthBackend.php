<?php
/**               -JMJ-
 *
 * FreeIPA/Apache authentication backend
 *
 * @author redneckcatholic
 * @license https://opensource.org/licenses/BSD-2-Clause
 * @version 0.01
 *
 * This authentication backend assumes that authentication has been configured
 * in Apache using the local FreeIPA domain. The only reason to use this module
 * (rather than the included Apache backend) is to strip the realm component
 * from the REMOTE_USER variable (GssapiLocalName is broken under gssproxy).
 *
 * php-ldap compiled with SASL support is required, along with accessible
 * kerberos credentials. Check the README for more information.
 *
 * Add this backend in server.php with the following invocation:
 *
 *   $ipa = new \FreeIPA\Connection();
 *   $allowedGroups = ['sabredav-access'];
 *   $authBackend = new \FreeIpa\AuthBackend($ipa, $allowedGroups);
 *
 * If the $allowedGroups argument is given, then membership in at least one of
 * the specified groups is required to login.
 *
 * If the $allowedGroups argument is not given (or any empty array is provided),
 * then no group memberships are checked.
 */

declare(strict_types=1);

namespace FreeIPA;

use \Sabre\HTTP\RequestInterface;
use \Sabre\HTTP\ResponseInterface;

class AuthBackend implements \Sabre\DAV\Auth\Backend\BackendInterface {

  const PRINCIPAL_PREFIX = 'principals/';

  protected $ipa;
  protected $allowedGroups;

  public function __construct(\FreeIPA\Connection $ipa, $allowedGroups = []) {
    $this->ipa = $ipa;
    $this->allowedGroups = $allowedGroups;
  }

  /**
   * When this method is called, the backend must check if authentication was
   * successful.
   *
   * The returned value must be one of the following
   *
   * [true, "principals/username"]
   * [false, "reason for failure"]
   *
   * If authentication was successful, it's expected that the authentication
   * backend returns a so-called principal url.
   *
   * Examples of a principal url:
   *
   * principals/admin
   * principals/user1
   * principals/users/joe
   * principals/uid/123457
   *
   * If you don't use WebDAV ACL (RFC3744) we recommend that you simply
   * return a string such as:
   *
   * principals/users/[username]
   *
   * @return array
   */
  public function check(RequestInterface $request, ResponseInterface $response) {
    $remoteUser = $request->getRawServerValue('REMOTE_USER');

    if (is_null($remoteUser)) {
      return [false, 'REMOTE_USER variable not set'];
    }

    /* If REMOTE_USER has a realm component, and the realm does not match the
     * local FreeIPA kerberos realm, deny the request.
     */
    $userParts = explode('@', $remoteUser, 2);

    if (count($userParts) == 2 && $userParts[1] != $this->ipa->getRealm()) {
      return [false, "REMOTE_USER has unknown realm: {$userParts[1]}"];
    }

    if (!User::get($this->ipa, $userParts[0], [], null, $this->allowedGroups)) {
      return [false, "user {$userParts[0]} failed group authorization"];
    }

    return [true, self::PRINCIPAL_PREFIX . $userParts[0]];
  }

  /**
   * This method is called when a user could not be authenticated, and
   * authentication was required for the current request.
   *
   * This gives you the opportunity to set authentication headers. The 401
   * status code will already be set.
   *
   * In this case of Basic Auth, this would for example mean that the
   * following header needs to be set:
   *
   * $response->addHeader('WWW-Authenticate', 'Basic realm=SabreDAV');
   *
   * Keep in mind that in the case of multiple authentication backends, other
   * WWW-Authenticate headers may already have been set, and you'll want to
   * append your own WWW-Authenticate header instead of overwriting the
   * existing one.
   */
  public function challenge(RequestInterface $request, ResponseInterface $response) {
    // intentional no-op
  }
}
