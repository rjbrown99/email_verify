<?php

/**
 * @file
 *   Configuration page for email verify module.
 */

/**
 * Page generation function for admin/settings/email_verify
 */
function email_verify_admin_page() {
  $output = '';
  return $output . drupal_get_form('email_verify_admin_form');
}

/**
 * Form builder; Displays configuration page.
 */
function email_verify_admin_form($form_state) {
  $form = array();

  $form['email_verify_settings']['email_verify_whitelist'] = array(
    '#type'           => 'textarea',
    '#title'          => t('Domain whitelist'),
    '#default_value'  => variable_get('email_verify_whitelist', FALSE),
    '#description'    => t('A list of domains, in the form of google.com with one domain per line, that should not have the more advanced user checks performed.'),
  );

  return system_settings_form($form);
}
