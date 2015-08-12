<?php


function em_notify_unread_cron() {
    $last_notify = variable_get('em_notify_unread_last', 0);

    $result = db_query("SELECT a.with, a.user, count(a.sort_id) as nb FROM prosodyarchive AS a 
INNER JOIN prosodychatmarkers AS markers ON (markers.archive_key=a.key AND markers.mark<2)
WHERE a.when > :lastrun
GROUP BY a.with, a.user
ORDER BY a.with, a.user ", array(
      ':lastrun' => $last_notify,
    ));

    if ($result) {
        $current_recipient = 0;
        $current_sender = 0;
        $data = array();
        $recipients = array();
        while ($row = $result->fetchAssoc()) {
           $recipients[$row['with']][$row['user']] = $row['nb'];
        }
        
        foreach ($recipients as $jid => $senders) {
            $message = new stdClass();
            $message->unreads = "";
            $current_uid = str_replace('@'.EXTENDED_MESSAGING_XMPP_DOMAIN,'',$jid);
            $current_user = user_load( $current_uid);
            $settings = _em_notify_settings($current_uid);
            if ( _em_notify_is_enabled($current_uid) && extended_messaging_user_online($current_user) != 'online') {
                $message->recipient = $current_user;
                foreach ($senders as $uid => $nb) {
                    $account = user_load($uid);
                    $message->unreads .= l($account->name, em_messagesui_url_to($account , array('absolute'=>true)) )." ({$nb})\n";
                }
                $params['recipient'] = $current_user;
                $params['message'] = $message;
                $options = array(
                    'language' => user_preferred_language($params['recipient']),
                    // Don't sanitize output since this is used in an email, not a browser.
                    'sanitize' => FALSE,
                    // Custom token to avoid custom token handling.
                    'privatemsg-display-invalid' => FALSE,
                );
                $from = trim(token_replace(variable_get('em_notify_from', ''), $data, $options));
                drupal_mail('em_notify', 'notice', $current_user->mail, user_preferred_language($current_user), $params, !empty($from) ? $from : NULL); //$current_user->mail
                _em_notify_settings_update($current_uid, $settings['freq'], time() ); 
                //dpm($params);
            }
        }
    }

    variable_set('em_notify_unread_last', time());
}
