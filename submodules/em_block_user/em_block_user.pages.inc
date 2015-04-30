<?php

/**
 * @file
 * User menu callbacks for em_block_user.module.
 */

function em_block_user_form(&$form_state, $author) {

  global $user;

  $desc = 'Please confirm your action';
  // Tell the submit handler to process the form
  $form['process'] = array('#type' => 'hidden', '#value' => 'true');
  // Make sure the form redirects in the end
  $form['destination'] = array('#type' => 'hidden', '#value' => 'messages/blocked');

    if (em_block_user_has_blocked($author, $user)) {

        $form['block_action'] = array(
            '#type' => 'value',
            '#value' => 'unblock_user',
        );
    } else {
        $form['block_action'] = array(
            '#type' => 'value',
            '#value' => 'block_user',
        );
    }

  return confirm_form($form,
      'Are you sure?',
      'example/add',
      $desc,
      'Continue',
      'Back');

}

/**
 * Submit callback for block user confirmation form.
 */
function em_block_user_form_submit($form, &$form_state) {
  global $user;

  $author = user_load($form['#parameters'][2]->uid);
  $host = EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN;

  if ($form_state['values']['confirm']) {

      switch ($form_state['values']['block_action']) {

          case 'block_user':

              $result = db_query("SELECT * FROM {prosody} WHERE `store` = 'privacy' AND `user` = %d", $user->uid);

              $row = db_fetch_object($result);

              if(FALSE !== $row) {
                  $value = json_decode($row->value, true);

                  $value['forbidden']['items'][] = array(
                      'message' => false,
                      'type' => 'jid',
                      'action' => "deny",
                      'order' => 4,
                      'value' => $author->uid.'@'.$host,
                      'presence-in' => false,
                      'iq' => false,
                      'presence-out' => false
                  );

                  $value = json_encode($value);

                  db_query("UPDATE {prosody} SET value = '%s' WHERE user = %d AND store = 'privacy'", $value, $user->uid);
              } else {

                  $user = $user->uid;
                  $store = 'privacy';
                  $key = 'lists';
                  $type = 'json';

                  $value = array(
                      'forbidden' => array(
                          'name' => 'forbidden',
                          'items' => array(
                              array(
                                  'message' => false,
                                  'action' => 'allow',
                                  'presense-out' => false,
                                  'presense-in' => false,
                                  'iq' => false,
                                  'order' => 2
                              ),
                              array(
                                  'message' => false,
                                  'type' => 'jid',
                                  'action' => "deny",
                                  'order' => 4,
                                  'value' => $author->uid.'@'.$host,
                                  'presence-in' => false,
                                  'iq' => false,
                                  'presence-out' => false
                              )
                          )
                      ),
                  );

                  $value = json_encode($value);

                  db_query("INSERT INTO {prosody} (`host`, `user`, `store`, `key`, `type`, `value`) VALUES ( '%s' , '%s', '%s', '%s', '%s', '%s')", $host, $user, $store, $key, $type, $value);
              }

              drupal_set_message(t('The user has been blocked from sending you any further messages.'));
              break;

          case 'unblock_user':

              $result = db_query("SELECT * FROM {prosody} WHERE `store` = 'privacy' AND `user` = %d", $user->uid);

              while ($row = db_fetch_object($result)) {
                  $value = json_decode($row->value, true);

                  foreach($value['forbidden']['items'] as $key => $item) {
                      if($item['action'] == 'deny') {
                          list($user_id) =  explode("@", $item['value'], 2);

                          if($user_id == $author->uid) {
                                unset($value['forbidden']['items'][$key]);
                          }
                      }
                  }
              }

              $value = json_encode($value);
              db_query("UPDATE {prosody} SET value = '%s' WHERE user = %d AND store = 'privacy'", $value, $user->uid);

              drupal_set_message(t('The user is now allowed to send you new messages.'));
              break;
      }

  }
  $form_state['redirect'] = $form_state['values']['destination'];
}

/**
 * Checks if user exists in users table
 */
function pm_user_exists($uid) {
  return true;
}

/**
 * Formbuilder function to build a simple form to block users.
 */
function em_block_user_list() {
  global $user;

  $form['new'] = array(
    '#type'   => 'fieldset',
    '#title'  => t('Block a user'),
  );
  $form['new']['name'] = array(
    '#type' => 'textfield',
    '#title' => t('Username'),
    '#autocomplete_path' => 'messages/user-name-autocomplete',
    '#description'        => t('Separate multiple names with commas.'),
    '#required'          => TRUE,
  );
  $form['new']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Block user'),
    '#validate' => array('em_block_user_block_validate'),
    '#submit' => array('em_block_user_block_submit'),
  );

  $header = array(
    array(
      'data' => t('Username'),
      'field' => 'u.name',
      'sort'  => 'asc',
      ),
    array(
      'data' => t('Operations'),
      ),
  );

  $results = db_query("SELECT * FROM {prosody} WHERE `store` = 'privacy' AND `user` = %d", $user->uid);
  $blocked_users = array();

  while ($row = db_fetch_object($results)) {
    $value = json_decode($row->value, true);

    foreach($value['forbidden']['items'] as $item) {
      if($item['action'] == 'deny') {
        list($user_id) =  explode("@", $item['value'], 2);

        if(pm_user_exists($user_id)) { // show only existing users
          $blocked_users[] = array(
              theme('username', user_load($user_id)),
              l(t('unblock'), 'messages/block/' . $user_id, array('query' => drupal_get_destination())),
          );
        }
      }
    }
  }

  $form['#header'] = $header;
  $form['#rows'] = $blocked_users;

  return $form;
}

/**
 * Validate user names.
 */
function em_block_user_block_validate($form, &$form_state) {
  global $user;
  list($accounts, $invalid) = _privatemsg_parse_userstring($form_state['values']['name'], array('user'));
  // Remove accounts that can not be blocked.
  if (!empty($accounts)) {
    foreach ($accounts as $id => $account) {

      // Check if the user can not be blocked because of a rule.
      if (_em_block_user_rule_exists($account, $user, PM_BLOCK_USER_DISALLOW_BLOCKING)) {
        drupal_set_message(t('You are not allowed to block !account.', array('!account' => theme('username', array('account' => $account)))), 'warning');
        unset($accounts[$id]);
        continue;
      }
      // Check if the user is already blocked.
      if (em_block_user_has_blocked($account, $user)) {
        drupal_set_message(t('You have already blocked !account.', array('!account' => theme('username', array('account' => $account)))), 'warning');
        unset($accounts[$id]);
        continue;
      }
      // Do not allow users to block themself.
      if ($user->uid == $account->uid) {
        drupal_set_message(t('You can not block yourself.'), 'warning');
        unset($accounts[$id]);
        continue;
      }
    }
  }
  // Display warning about invalid user names.
  if (!empty($invalid)) {
    drupal_set_message(t('The following users do not exist: @invalid.', array('@invalid' => implode(", ", $invalid))), 'warning');
  }
  // If there are no accounts left, display error.
  if (empty($accounts)) {
    form_set_error('name', t('You are either not allowed to block these users or the users do not exist.'));
  }
  else {
    $form_state['valid_accounts'] = $accounts;
  }
}

/**
 * Submit callback for block user form.
 */
function em_block_user_block_submit($form, &$form_state) {
  global $user;
  $host = EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN;

  foreach ($form_state['valid_accounts'] as $account) {

    $result = db_query("SELECT * FROM {prosody} WHERE `store` = 'privacy' AND `user` = %d", $user->uid);

    $row = db_fetch_object($result);


    if(FALSE !== $row) {
      $value = json_decode($row->value, true);

      $value['forbidden']['items'][] = array(
          'message' => false,
          'type' => 'jid',
          'action' => "deny",
          'order' => 4,
          'value' => $account->uid.'@'.$host,
          'presence-in' => false,
          'iq' => false,
          'presence-out' => false
      );

      $value = json_encode($value);

      db_query("UPDATE {prosody} SET value = '%s' WHERE user = %d AND store = 'privacy'", $value, $user->uid);
    } else {

      $value = array(
          'forbidden' => array(
              'name' => 'forbidden',
              'items' => array(
                  array(
                      'message' => false,
                      'action' => 'allow',
                      'presense-out' => false,
                      'presense-in' => false,
                      'iq' => false,
                      'order' => 2
                  ),
                  array(
                      'message' => false,
                      'type' => 'jid',
                      'action' => "deny",
                      'order' => 4,
                      'value' => $account->uid.'@'.$host,
                      'presence-in' => false,
                      'iq' => false,
                      'presence-out' => false
                  )
              )
          ),
      );

        $data = array(
            'host' => $host,
            'user' => $user->uid,
            'store' => 'privacy',
            'key' => 'lists',
            'type' => 'json',
            'value' => json_encode($value)
        );

      db_query("INSERT INTO {prosody} (`host`, `user`, `store`, `key`, `type`, `value`) VALUES ( '%s' , '%s', '%s', '%s', '%s', '%s')", $data['host'], $data['user'], $data['store'], $data['key'], $data['type'], $data['value']);

    }

    drupal_set_message(t( $account->name . ' has been blocked from sending you any further messages.', array('!author' => theme('username', array('account' => $account)))));
  }

    $form_state['redirect'] = 'messages/blocked';
}

/**
 * Theme function to theme the blocked user listing.
 */
function theme_em_block_user_list($form) {
  return drupal_render_children($form) . theme('table', $form['#header'], $form['#rows']) . theme('pager');
}

/**
 * Renders children of an element and concatenates them.
 *
 * @param array $element
 *   The structured array whose children shall be rendered.
 * @param array $children_keys
 *   (optional) If the keys of the element's children are already known, they
 *   can be passed in to save another run of element_children().
 *
 * @return string
 *   The rendered HTML of all children of the element.

 * @see drupal_render()
 */
function drupal_render_children(&$element, $children_keys = NULL) {
    if ($children_keys === NULL) {
        $children_keys = element_children($element);
    }
    $output = '';
    foreach ($children_keys as $key) {
        if (!empty($element[$key])) {
            $output .= drupal_render($element[$key]);
        }
    }
    return $output;
}

