<?php
/**               -JMJ-
 *
 * FreeIPA connection definition
 *
 * @author redneckcatholic
 * @license https://opensource.org/licenses/BSD-2-Clause
 * @version 0.01
 *
 * This class represents a connection to a FreeIPA domain. An instance should
 * be instansiated in server.php and passed to the FreeIpaAuthentication and
 * FreeIpaPrincipal backends.
 *
 * No arguments are necessary, but you may override the autodetection with
 * the following invocation:
 *
 *   new \FreeIPA\Connection((
 *     domain = null,
 *     realm = null,
 *     baseDn = null,
 *     ldapUri = null
 *   )
 */

declare(strict_types=1);

namespace FreeIPA;

class Connection {

  protected $realm;
  protected $domain;
  protected $baseDn;
  protected $ldapUri;
  protected $ldapConn;

  protected function discoverDnsDomain() {
    if ($localFqdn = gethostbyaddr(gethostbyname(gethostname()))) {
      $domain = strtolower(explode('.', $localFqdn, 2)[1]);
      if (!in_array($domain, [$localFqdn, 'localhost', 'localdomain', 'localhost.localdomain'])) {
        $this->domain = $domain;
        return true;
      }
    }
    return false;
  }

  protected function discoverKerberosRealm() {
    if ($kerberosTxtRecord = dns_get_record("_kerberos.{$this->domain}", DNS_TXT)) {
      $this->realm = $kerberosTxtRecord[0]['txt'];
      return true;
    }
    return false;
  }

  protected function discoverLdapServers() {
    if ($ldapSrvRecords = dns_get_record("_ldap._tcp.{$this->domain}", DNS_SRV)) {
      foreach ($ldapSrvRecords as $record) {
        $ldapUris[] = "ldap://$record[target]:$record[port]";
      }
      $this->ldapUri = implode(' ', $ldapUris);
      return true;
    }
    return false;
  }

  protected function discoverBaseDn() {
    $results = ldap_read($this->ldapConn, '', 'objectClass=*', ['defaultnamingcontext']);
    if ($results && ldap_count_entries($this->ldapConn, $results) == 1) {
      if ($rootDse = ldap_first_entry($this->ldapConn, $results)) {
        $attributes = ldap_get_attributes($this->ldapConn, $rootDse);
        if ($attributes['defaultnamingcontext']['count'] == 1) {
          $this->baseDn = $attributes['defaultnamingcontext'][0];
          return true;
        }
      }
    }
    return false;
  }

  protected function guessBaseDnFromRealm() {
    $this->baseDn = implode(',', preg_filter('/^/', 'dc=', explode('.', strtolower($this->realm))));
  }

  public function __construct($domain = null, $realm = null, $baseDn = null, $ldapUri = null) {
    if (!function_exists('ldap_connect')) {
      throw new Exception('FreeIPA integration requires php-ldap, and it is not installed');
    }

    // get local domain
    if (!empty($domain)) {
      $this->domain = $domain;
    } elseif (!$this->discoverDnsDomain()) {
      throw new Exception("Failed to discover local FreeIPA domain");
    }

    // get local realm
    if (!empty($realm)) {
      $this->realm = $realm;
    } elseif (!$this->discoverKerberosRealm()) {
      $this->realm = strtoupper($this->domain);
    }

    // get ldap servers
    if (!empty($ldapUri)) {
      $this->ldapUri = $ldapUri;
    } elseif (!$this->DiscoverLdapServers()) {
      throw new Exception("Failed to discover local LDAP servers via DNS");
    }

    // connect to ldap server
    if (!($this->ldapConn = ldap_connect($this->ldapUri))) {
      throw new Exception("Failed to connect to FreeIPA LDAP server");
    }

    // set protocol version 3
    if (!ldap_set_option($this->ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3)) {
      throw new Exception("Failed to set LDAP protocol version");
    }

    // start TLS session
    if(!ldap_start_tls($this->ldapConn)) {
      throw new Exception("Failed to establish TLS session with LDAP server");
    }

    // bind to ldap server using kerberos credentials
    if (!ldap_sasl_bind($this->ldapConn, '', '', 'GSSAPI')) {
      throw new Exception("Failed to bind to LDAP server");
    }

    // get base dn
    if (!empty($baseDn)) {
      $this->basedn = $baseDn;
    } elseif (!$this->discoverBaseDn()) {
      $this->guessBaseDnFromRealm();
    }
  }

  public function search($base = null, $filter = null, $attributes = []) {
    error_log("ipa->search($base, $filter)");
    if ($filter == null) {
      $filter = '(objectClass=*)';
    }

    if ($result = ldap_search($this->ldapConn, ($base ? $base.','.$this->baseDn : $this->baseDn), $filter, $attributes)) {
      if ($entries = ldap_get_entries($this->ldapConn, $result)) {
        if ($entries['count'] > 0) {
          return $entries;
        }
      }
    }
    return false;
  }

  public function read($base, $filter = '(objectClass=*)', $attributes = []) {
    error_log("ipa->read($base, $filter)");
    if ($filter == null) {
      $filter = '(objectClass=*)';
    }

    if ($result = ldap_read($this->ldapConn, $base . ',' . $this->baseDn, $filter, $attributes)) {
      if ($entries = ldap_get_entries($this->ldapConn, $result)) {
        if ($entries['count'] > 0) {
          return $entries[0];
        }
      }
    }
    return false;
  }

  public function getBaseDn() {
    return $this->baseDn;
  }

  public function resolveDn(...$components) {
    return implode(',', array_merge($components, [$this->baseDn]));
  }

  public function getRealm() {
    return $this->realm;
  }
}
