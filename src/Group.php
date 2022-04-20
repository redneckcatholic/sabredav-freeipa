<?php
/**               -JMJ-
 *
 * FreeIPA group definition
 *
 * @author redneckcatholic
 * @license https://opensource.org/licenses/BSD-2-Clause
 * @version 0.01
 *
 * This class represents a FreeIPA group object. It cannot not be instantiated
 * directly. Rather, use the static Group::get() or Group::search() methods
 * to retrieve one or more groups.
 */

declare(strict_types=1);

namespace FreeIPA;

class Group {
  const PRINCIPAL_PREFIX  = 'principals/';
  const LDAP_CONTAINER    = 'cn=groups,cn=accounts';
  const LDAP_OBJECT_CLASS = 'groupofnames';
  const LDAP_ATTRIBUTES   = ['cn', 'description'];

  const LDAP_FIELD_MAP = [
    '{DAV:}displayname' => 'description',
    '{http://sabredav.org/ns}email-address' => 'mail'
  ];

  protected $name;
  protected $description;

  protected function __construct($name, $description) {
    $this->name = $name;
    $this->description = $description;
  }

  protected static function fromLdapEntry($entry) {
    return new self(
      $entry['cn'][0],
      isset($entry['description'][0]) ? $entry['description'][0] : $entry['cn'][0]
    );
  }

  protected static function getRelativeDn($groupname) {
    return 'cn=' . ldap_escape($groupname) . ',' . self::LDAP_CONTAINER;
  }

  public static function search($ipaConn, $searchProperties = [], $test = 'anyof', $allowedGroups = []) {
    $groups = [];

    // for each group matching $filter
    if ($entries = $ipaConn->search(
      self::LDAP_CONTAINER,
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        Util::buildMemberOfFilter($ipaConn, $allowedGroups, true),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      for ($i = 0; $i < $entries['count']; $i++) {
        $groups[] = self::fromLdapEntry($entries[$i]);
      }
    }
    return $groups;
  }

  public static function get($ipaConn, $groupname, $searchProperties = [], $test = 'anyof', $allowedGroups = []) {
    if ($entry = $ipaConn->read(
      self::getRelativeDn($groupname),
      Util::buildFilter('allof',
        ['objectClass', self::LDAP_OBJECT_CLASS],
        Util::buildMemberOfFilter($ipaConn, $allowedGroups, true),
        Util::buildPrincipalFilter($searchProperties, self::LDAP_FIELD_MAP, $test)),
      self::LDAP_ATTRIBUTES))
    {
      return self::fromLdapEntry($entry);
    }

    return null;
  }

  public function getMemberPrincipals($ipaConn, $allowedGroups = []) {
    $memberPrincipals = [];

    if ($entries = $ipaConn->search(
      User::LDAP_CONTAINER,
      Util::buildFilter('allof',
        ['objectClass', User::LDAP_OBJECT_CLASS],
        ['memberof',  $ipaConn->resolveDn('cn='.ldap_escape($this->name), self::LDAP_CONTAINER)],
        Util::buildMemberOfFilter($ipaConn, $allowedGroups)),
      ['uid']))
    {
      for ($i = 0; $i < $entries['count']; $i++) {
        $memberPrincipals[] = User::PRINCIPAL_PREFIX . $entries[$i]['uid'][0];
      }
    }

    return $memberPrincipals;
  }

  public function toPrincipal() {
    return [
      'uri' => self::PRINCIPAL_PREFIX . $this->name,
      '{DAV:}displayname' => $this->description
    ];
  }

  public function getName() {
    return $this->name;
  }
}
