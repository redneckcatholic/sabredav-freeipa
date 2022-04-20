<?php
/**               -JMJ-
 *
 * FreeIPA user definition
 *
 * @author redneckcatholic
 * @license https://opensource.org/licenses/BSD-2-Clause
 * @version 0.01
 *
 * This class represents a FreeIPA user object. It cannot not be instantiated
 * directly. Rather, use the static User::get() or User::search() methods
 * to retrieve one or more users.
 */

declare(strict_types=1);

namespace FreeIPA;

class User {
  const PRINCIPAL_PREFIX  = 'principals/';
  const LDAP_CONTAINER    = 'cn=users,cn=accounts';
  const LDAP_OBJECT_CLASS = 'person';
  const LDAP_ATTRIBUTES   = ['uid', 'displayname', 'mail'];

  const LDAP_FIELD_MAP = [
    '{DAV:}displayname' => 'displayname',
    '{http://sabredav.org/ns}email-address' => 'mail'
  ];

  protected $uid;
  protected $displayName;
  protected $email;

  protected function __construct($uid, $displayName, $email) {
    $this->uid = $uid;
    $this->displayName = $displayName;
    $this->email = $email;
  }

  protected static function getRelativeDn($uid) {
    return 'uid=' . ldap_escape($uid) . ',' . self::LDAP_CONTAINER;
  }

  protected static function fromLdapEntry($entry) {
    return new self(
      $entry['uid'][0],
      isset($entry['displayname'][0]) ? $entry['displayname'][0] : $entry['uid'][0],
      $entry['mail'][0]
    );
  }

  public static function search($ipaConn, $searchProperties = [], $test = 'allof', $allowedGroups = []) {
    $users = [];

    // for each user matching filter
    if ($entries = $ipaConn->search(
      self::LDAP_CONTAINER,
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        'mail=*',
        Util::buildMemberOfFilter($ipaConn, $allowedGroups),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      for ($i = 0; $i < $entries['count']; $i++) {
        $users[] = self::fromLdapEntry($entries[$i]);
      }
    }
    return $users;
  }

  public static function get($ipaConn, $username, $searchProperties = [], $test = 'allof', $allowedGroups = []) {
    if ($entry = $ipaConn->read(
      self::getRelativeDn($username),
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        'mail=*',
        Util::buildMemberOfFilter($ipaConn, $allowedGroups),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      return self::fromLdapEntry($entry);
    }
    return null;
  }

  public function getGroupPrincipals($ipaConn, $allowedGroups = []) {
    $groupPrincipals = [];

    // get the user's groups
    if ($userEntry = $ipaConn->read(
      self::getRelativeDn($this->uid),
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        'mail=*',
        Util::buildMemberOfFilter($ipaConn, $allowedGroups)),
      ['uid', 'memberof']))
    {
      // get all allowed groups (and resolve any nested groups)
      if ($allowedGroupEntries = $ipaConn->search(
        Group::LDAP_CONTAINER,
        Util::buildFilter('allof',
          ['objectClass', Group::LDAP_OBJECT_CLASS],
          Util::buildMemberOfFilter($ipaConn, $allowedGroups, true)),
        ['cn']))
      {
        // get the intersection of user's groups and allowed groups
        for ($i = 0; $i < $userEntry['memberof']['count']; $i++) {
          for ($j = 0; $j < $allowedGroupEntries['count']; $j++) {
            if ($userEntry['memberof'][$i] == $allowedGroupEntries[$j]['dn']) {
              $groupPrincipals[] = Group::PRINCIPAL_PREFIX . $allowedGroupEntries[$j]['cn'][0];
            }
          }
        }
      }
    }
    return $groupPrincipals;
  }

  public function toPrincipal() {
    return [
      'uri' => self::PRINCIPAL_PREFIX . $this->uid,
      '{DAV:}displayname' => $this->displayName,
      '{http://sabredav.org/ns}email-address' => $this->email
    ];
  }

  public function getUid() {
    return $this->uid;
  }
}
