<?php

/**
 * @file
 * Check the email for email_verify module.
 */

/**
 * Primary function for validating email addresses.
 *
 * @param string $mail
 *   An email address to check, such as drupal@drupal.org.
 *
 * @return
 *   Empty if address is valid, a text error string if it's invalid.
 */
function _email_verify_check($mail) {
  if (!valid_email_address($mail)) {
    // The address is syntactically incorrect.
    // The problem will be caught by the 'user' module anyway, so we avoid
    // duplicating the error reporting here, just return.
    return;
  }

  $host = substr(strchr($mail, '@'), 1);

  // If the domain is not cached, perform tests
  if (!_email_verify_checkdb($host)) {
    // Let's see if we can find anything about this host in the DNS
    if (!checkdnsrr($host, 'ANY')) {
      return t('Email host %host invalid, please retry.', array('%host' => "$host"));
    }

    if ($whitelist = variable_get('email_verify_whitelist', FALSE)) {
      $whitelist = explode("\n", $whitelist);
      if (in_array($host, $whitelist)) {
        return;
      }
    }

    // What SMTP servers should we contact?
    $mx_hosts = array();
    if (!getmxrr($host, $mx_hosts)) {
      // When there is no MX record, the host itself should be used
      $mx_hosts[] = $host;
    }

    // Try to connect to one SMTP server
    foreach ($mx_hosts as $smtp) {
      $connect = @fsockopen($smtp, 25, $errno, $errstr, 15);
      if (!$connect) continue;
      if (ereg("^220", $out = fgets($connect, 1024))) {
        // OK, we have a SMTP connection
        break;
      }
      else {
        // The SMTP server probably does not like us
        // (dynamic/residential IP for aol.com for instance)
        // Be on the safe side and accept the address, at least it has a valid
        // domain part...
        watchdog('email_verify', "Could not verify email address at host $host: $out");
        return;
      }
    }

    if (!$connect) {
      return t('Email host %host is invalid, please contact us for clarification.', array('%host' => "$host"));
    }

    $from = variable_get('site_mail', ini_get('sendmail_from'));

    // Extract the <...> part if there is one
    if (preg_match('/\<(.*)\>/', $from, $match) > 0) {
      $from = $match[1];
    }

    $localhost = $_SERVER["HTTP_HOST"];
    if (!$localhost) { // Happens with HTTP/1.0
      // should be good enough for RFC compliant SMTP servers
      $localhost = 'localhost';
    }

    fputs($connect, "HELO $localhost\r\n");
    $out  = fgets($connect, 1024);
    fputs($connect, "MAIL FROM: <$from>\r\n");
    $from = fgets($connect, 1024);
    fputs($connect, "RCPT TO: <{$mail}>\r\n");
    $to   = fgets($connect, 1024);
    fputs($connect, "QUIT\r\n");
    fclose($connect);

    if (!ereg ("^250", $from)) {
      // Again, something went wrong before we could really test the address,
      // be on the safe side and accept it.
      watchdog('email_verify', "Could not verify email address at host $host: $from");
      return;
    }

    if (
      // This server does not like us
      // (noos.fr behaves like this for instance)
      ereg("(Client host|Helo command) rejected", $to) ||

      // Any 4xx error also means we couldn't really check
      // except 450, which is explcitely a non-existing mailbox:
      // 450 = "Requested mail action not taken: mailbox unavailable"
      ereg("^4", $to) && !ereg("^450", $to)) {

        // In those cases, accept the email, but log a warning
        watchdog('email_verify', "Could not verify email address at host $host: $to");
        return;
    }

    if (!ereg ("^250", $to)) {
      watchdog('email_verify', "Rejected email address: $mail. Reason: $to");
      return t('%mail is invalid, please contact us for clarification.', array('%mail' => "$mail"));
    }
    // If the previous checks pass, save the valid domain to the DB table.
    _email_verify_updatedb($host);
  }

  // Everything OK
  return;
}

/**
 * Lookup cached mail domain in the database.
 *
 * @param $host
 *   Valid host/domain portion of an email address, such as drupal.org.
 *
 * @return
 *   TRUE if domain is in the database and cache is valid, FALSE if a new check
 *   should be performed.
 */
function _email_verify_checkdb($host) {
  // Length of time a cached domain check is valid. Defaults to 30 days.
  $valid = variable_get('email_verify_cached_valid', EMAIL_VERIFY_CACHED_VALID);
  // Oldest timestamp for a valid domain
  $oldest = time() - $valid;

  $result = db_result(db_query("SELECT * FROM {email_verify} WHERE domain = '%s' AND validated >= %d AND status = 1 LIMIT 1", $host, $oldest));
  if ($result) {
    return TRUE;
  }

  return FALSE;
}

/**
 * Store successful domain checks in the database.
 *
 * @param $host
 *   The validated host/domain.
 *
 * @return
 *   Matches drupal_write_record: FALSE if it was not saved, SAVED_NEW or
 *   SAVED_UPDATED if it succeeded.
 */
function _email_verify_updatedb($host) {
  // The record to save to the database
  $update = new stdClass;
  $update->domain = $host;
  $update->validated = time();
  $update->status = 1;

  $result = db_result(db_query("SELECT * FROM {email_verify} WHERE domain = '%s'", $host));
  if ($result) {
    return drupal_write_record('email_verify', $update, 'domain');
  }
  else {
    return drupal_write_record('email_verify', $update);
  }
}

/**
 * Clean the database of old records.
 */
function _email_verify_cleandb() {
  // Length of time a cached domain check is valid. Defaults to 30 days.
  $valid = variable_get('email_verify_cached_valid', EMAIL_VERIFY_CACHED_VALID);
  $oldest = time() - $valid;

  $result = db_query("SELECT * FROM {email_verify} WHERE validated <= %d", $oldest);
  while ($record = db_fetch_array($result)) {
    db_query("DELETE FROM {email_verify} WHERE domain = '%s'", $record['domain']);
  }
}
