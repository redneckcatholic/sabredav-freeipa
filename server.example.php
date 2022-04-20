<?php
/**               -JMJ-
 *
 * Example sabredav configuration for FreeIPA
 *
 * @author redneckcatholic
 * @license https://opensource.org/licenses/BSD-2-Clause
 * @version 0.01
 *
 * Rename this file to config.php and edit to suit your needs. After running
 * `composer install` in this directory, you should be good to go.
 */

// timezone
date_default_timezone_set('UTC');

// database
$pdo = new PDO('pgsql:dbname=sabredav;host=postgres.example.com', 'sabredav');
$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);

// autoloader
require_once 'vendor/autoload.php';

// freeipa
$ipa = new \FreeIPA\Connection();
$allowedGroups = [
  'dav-access'
];

// backends
$authBackend      = new \FreeIPA\AuthBackend($ipa, $allowedGroups);
$principalBackend = new \FreeIPA\PrincipalBackend($ipa, $allowedGroups);
$caldavBackend    = new \Sabre\CalDAV\Backend\PDO($pdo);
$carddavBackend   = new \Sabre\CardDAV\Backend\PDO($pdo);

// directory structure
$server = new Sabre\DAV\Server([
  new \Sabre\CalDAV\Principal\Collection($principalBackend),
  new \Sabre\CalDAV\CalendarRoot($principalBackend, $caldavBackend),
  new \Sabre\CardDAV\AddressBookRoot($principalBackend, $carddavBackend)
]);

// plugins
$server->addPlugin(new \Sabre\DAV\Auth\Plugin($authBackend,'SabreDAV'));
$server->addPlugin(new \Sabre\DAV\Browser\Plugin());
$server->addPlugin(new \Sabre\DAV\Sync\Plugin());
$server->addPlugin(new \Sabre\DAV\Sharing\Plugin());

$aclPlugin = new \Sabre\DAVACL\Plugin();
$aclPlugin->hideNodesFromListings = true;
$server->addPlugin($aclPlugin);

// caldav plugins
$server->addPlugin(new \Sabre\CalDAV\Plugin());
$server->addPlugin(new \Sabre\CalDAV\Schedule\Plugin());
$server->addPlugin(new \Sabre\CalDAV\Schedule\IMipPlugin('calendar-noreply@example.com'));
$server->addPlugin(new \Sabre\CalDAV\Subscriptions\Plugin());
$server->addPlugin(new \Sabre\CalDAV\Notifications\Plugin());
$server->addPlugin(new \Sabre\CalDAV\SharingPlugin());
$server->addPlugin(new \Sabre\CalDAV\ICSExportPlugin());

// carddav plugins
$server->addPlugin(new \Sabre\CardDAV\Plugin());
$server->addPlugin(new \Sabre\CardDAV\VCFExportPlugin());

// lets goooooo
$server->exec();