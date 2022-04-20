<?php
/**               -JMJ-
 *
 * FreeIPA utility class
 *
 * @author redneckcatholic
 * @license https://opensource.org/licenses/BSD-2-Clause
 * @version 0.01
 *
 * This class contains various helper functions for querying FreeIPA.
 * Static methods only.
 */

declare(strict_types=1);

namespace FreeIPA;

class Util {

  private function __construct() { }

  public static function buildFilter($test, ...$conditions) {
    $filter = '';

    foreach ($conditions as $condition) {
      if (is_array($condition)) {
        for ($i = 0; $i < count($condition); $i+=2) {
          $filter .= "({$condition[$i]}={$condition[$i+1]})";
        }
      } elseif (!empty($condition)) {
        if ($condition[0] != '(' && $condition[-1] != ')') {
          $condition = "($condition)";
        }
        $filter .= $condition;
      }
    }

    if ($filter) {
      $filter = '(' . ($test === 'anyof' ? '|' : '&') . $filter . ')';
    }

    return $filter;
  }

  public static function buildPrincipalFilter($searchProperties = [], $fieldMap = [], $test = 'allof') {
    $conditions = [];

    foreach ($searchProperties as $property => $value) {
      if (isset($fieldMap[$property])) {
        $conditions[] = [$fieldMap[$property].':caseIgnoreIA5Match:', '*'.ldap_escape($value).'*'];
      } else {
        throw new \Sabre\DAV\Exception\BadRequest("Unknown property: $property");
      }
    }

    return self::buildFilter($test, ...$conditions);
  }

  public static function buildMemberOfFilter($ipaConn, $groupnames, $includeSelf = false) {
    $conditions = [];

    foreach ($groupnames as $groupname) {
      $conditions[] = ['memberOf', $ipaConn->resolveDn('cn='.ldap_escape($groupname), Group::LDAP_CONTAINER)];
      if ($includeSelf) {
        $conditions[] = 'cn=' . ldap_escape($groupname);
      }
    }

    return self::buildFilter('anyof', ...$conditions);
  }
}
