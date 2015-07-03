<?php

/**
 * @file
 * User menu callbacks for pm_block_user.module.
 */

function pm_block_user_form($form, $form_state, $author) {
  global $user;

  $form['author'] = array(
    '#type' => 'value',
    '#value' => $author,
  );
    $form['recipient'] = array(
    '#type' => 'value',
    '#value' => $user,
  );
  $form['destination'] = array(
    '#type' => 'value',
    '#value' => isset($_GET['destination']) ? $_GET['destination'] : 'messages/',
  );
  if (pm_block_user_has_blocked($author, $user)) {
    $form['block_action'] = array(
      '#type' => 'value',
      '#value' => 'unblock_user',
    );
    return confirm_form($form,
      t('You have previously blocked "@author" from sending you any more messages. Are you sure you want to unblock this user?', array('@author' => privatemsg_recipient_format($author, array('plain' => TRUE)))),
      isset($_GET['destination']) ? $_GET['destination'] : 'messages/',
      '',
      t('Unblock @author', array('@author' => privatemsg_recipient_format($author, array('plain' => TRUE)))),
      t('Cancel')
    );
  }
  else {
    $form['block_action'] = array(
      '#type' => 'value',
      '#value' => 'block_user',
    );
    return confirm_form($form,
      t('Are you sure you want to block "@author" from sending you any more messages?', array('@author' => privatemsg_recipient_format($author, array('plain' => TRUE)))),
      isset($_GET['destination']) ? $_GET['destination'] : 'messages/',
      '',
      t('Block @author', array('@author' => privatemsg_recipient_format($author, array('plain' => TRUE)))),
      t('Cancel')
    );
  }
}

/**
 * Submit callback for block user confirmation form.
 */
function pm_block_user_form_submit($form, &$form_state) {
  if ($form_state['values']['confirm']) {
    switch ($form_state['values']['block_action']) {
      case 'block_user':



          $select = db_select('prosody', 'pmb')
              ->fields('pmb', array('value'))
              ->condition('pmb.user', $form_state['values']['recipient']->uid)
              ->condition('pmb.store', 'privacy');

          $rows = $select->execute();

            if($rows->rowCount() > 0) { //insert new row

                foreach($rows as $row) {

                    $value = json_decode($row->value, true);

                    $value['forbidden']['items'][] = array(
                        'message' => false,
                        'type' => 'jid',
                        'action' => "deny",
                        'order' => 4,
                        'value' => $form_state['values']['author']->uid.'@localhost',
                        'presence-in' => false,
                        'iq' => false,
                        'presence-out' => false
                    );

                    $value = json_encode($value);

                    db_query("UPDATE {prosody} SET value = '%s' WHERE user = %d AND store = 'privacy'", $value, $form_state['values']['recipient']->recipient);
                }

            } else if(false === $rows || $rows->rowCount() == 0 ) {

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
                                'value' => $form_state['values']['author']->uid.'@localhost',
                                'presence-in' => false,
                                'iq' => false,
                                'presence-out' => false
                            )
                        )
                    ),
                );

                $value = json_encode($value);

                $data = array(
                    'host' => 'localhost',
                    'user' => $form_state['values']['recipient']->uid,
                    'store' => 'privacy',
                    'key' => 'lists',
                    'type' => 'json',
                    'value' => json_encode($value)
                );

                $insert = db_insert('prosody')->fields(array('host', 'user', 'store', 'key', 'type', 'value'));
                $insert->values($data);
                $insert->execute();


            }

        drupal_set_message(t('@author has been blocked from sending you any further messages.', array('@author' => privatemsg_recipient_format($form_state['values']['author'], array('plain' => TRUE)))));
      break;
      case 'unblock_user':
          $select = db_select('prosody', 'pmb')
              ->fields('pmb', array('value'))
              ->condition('pmb.user', $form_state['values']['recipient']->uid)
              ->condition('pmb.store', 'privacy');

          foreach ($select->execute() as $row) {

              $value = json_decode($row->value, true);

              foreach($value['forbidden']['items'] as $key => $item) {
                  if($item['action'] == 'deny') {
                      list($user_id) =  explode("@", $item['value'], 2);

                      if($user_id == $form_state['values']['author']->uid) {
                          unset($value['forbidden']['items'][$key]);
                      }
                  }
              }
          }

          $value = json_encode($value);

          db_update('prosody')
              ->fields(array('value' => $value))
              ->condition('store', 'privacy')
              ->condition('user', $form_state['values']['recipient']->uid)
              ->execute();

//          db_query("UPDATE {prosody} SET value = '%s' WHERE user = %d AND store = 'privacy'", $value, $user->uid);

        drupal_set_message(t('@author is now allowed to send you new messages.', array('@author' => privatemsg_recipient_format($form_state['values']['author'], array('plain' => TRUE)))));
      break;
    }
  }
  $form_state['redirect'] = $form_state['values']['destination'];
}

function pm_user_exists() {
  return true;
}

/**
 * Formbuilder function to build a simple form to block users.
 */
function pm_block_user_list() {
  global $user;

  $form['new'] = array(
    '#type'   => 'fieldset',
    '#title'  => t('Block a user'),
  );
  $form['new']['name'] = array(
    '#type' => 'textfield',
    '#title' => t('Username'),
    '#autocomplete_path' => 'messages/user/autocomplete',
    '#description'        => t('Separate multiple names with commas.'),
    '#required'          => TRUE,
  );
  $form['new']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Block user'),
    '#validate' => array('pm_block_user_block_validate'),
    '#submit' => array('pm_block_user_block_submit'),
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

  $select = db_select('prosody', 'pmb')->extend('PagerDefault')->extend('TableSort')
    ->fields('pmb', array('value'))
    ->condition('pmb.user', $user->uid)
    ->condition('pmb.store', 'privacy')
    ->limit(20);

  $blocked_users = array();
  foreach ($select->execute() as $row) {

    $value = json_decode($row->value, true);

    foreach($value['forbidden']['items'] as $item) {
      if($item['action'] == 'deny') {
        list($user_id) =  explode("@", $item['value'], 2);

        if(pm_user_exists($user_id)) { // show only existing users
          $blocked_users[] = array(
              theme('username', array('account' => user_load($user_id))),
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
function pm_block_user_block_validate($form, &$form_state) {
  global $user;
  list($accounts, $invalid) = _privatemsg_parse_userstring($form_state['values']['name'], array('user'));
  // Remove accounts that can not be blocked.
  if (!empty($accounts)) {
    foreach ($accounts as $id => $account) {

      // Only authors can be blocked.
      if ($account->type != 'user') {
        drupal_set_message(t('Only users can be blocked.'));
        unset($accounts[$id]);
        continue;
      }

      // Check if the user can not be blocked because of a rule.
      if (_pm_block_user_rule_exists($account, $user, PM_BLOCK_USER_DISALLOW_BLOCKING)) {
        drupal_set_message(t('You are not allowed to block !account.', array('!account' => theme('username', array('account' => $account)))), 'warning');
        unset($accounts[$id]);
        continue;
      }

      // Check if the user is already blocked.
      if (pm_block_user_has_blocked($account, $user)) {
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
function pm_block_user_block_submit($form, &$form_state) {
  global $user;

  foreach ($form_state['valid_accounts'] as $account) {

    $select = db_select('prosody', 'pmb')->extend('PagerDefault')->extend('TableSort')
        ->fields('pmb', array('value'))
        ->condition('pmb.user', $user->uid)
        ->condition('pmb.store', 'privacy')
        ->limit(20);

    $rows = $select->execute();

    if($rows !== false && $rows->rowCount() > 0) {


        foreach($rows as $row) {

            $value = json_decode($row->value, true);

            $value['forbidden']['items'][] = array(
                'message' => false,
                'type' => 'jid',
                'action' => "deny",
                'order' => 4,
                'value' => $account->uid.'@localhost',
                'presence-in' => false,
                'iq' => false,
                'presence-out' => false
            );
            $value = json_encode($value);

            db_update('prosody')
                ->fields(array('value' => $value))
                ->condition('store', 'privacy')
                ->condition('user', $user->uid)
                ->execute();
        }

    } else if($rows === false || $rows->rowCount() == 0) { // new row

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
                      'value' => $account->uid.'@localhost',
                      'presence-in' => false,
                      'iq' => false,
                      'presence-out' => false
                  )
              )
          ),
      );

//      $data = array(
//          'host' => 'localhost',
//          'user' => $user->uid,
//          'store' => 'privacy',
//          'key' => 'lists',
//          'type' => 'json',
//          'value' => json_encode($value)
//      );

        db_insert('prosody')
            ->fields(array(
                'host' => 'localhost',
                'user' => $user->uid,
                'store' => 'privacy',
//                'key' => 'lists',
//                'type' => 'json',
                'value' => json_encode($value)
            ))
            ->execute();

    }
  }

  drupal_set_message(t('!author has been blocked from sending you any further messages.', array('!author' => theme('username', array('account' => $account)))));

}

/**
 * Theme function to theme the blocked user listing.
 */
function theme_pm_block_user_list($variables) {
  $form = $variables['form'];
  return drupal_render_children($form) . theme('table', array('header' => $form['#header'], 'rows' =>  $form['#rows'])) . theme('pager');
}