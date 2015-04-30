<?php

/**
 * Set up batch for first and last name loading.
 *
 * This is where Drupal's Batch API comes into play.
 * It's as simple as defining $batch, and then calling batch_set($batch)
 */
function batch_demo_first_last() {

    // Update the user profiles to add values to newly added profile fields
    $batch = array(
        'title' => t('Updating Tables'),
        'operations' => array(),
        'finished' => '_batch_demo_update_finished',
        'init_message' => t('Initializing...'),
        'progress_message' => t('Fixed @current out of @total.'),
        'error_message' => t('Updating of tables encountered an error.'),
    );

    // Batch #1
    $batch['operations'][] = array('_batch_demo_fill_table_prosodyarchive', array());

    // Batch #2
    $batch['operations'][] = array('_batch_demo_fill_table_prosodychatmarkers', array());

    // Batch #3
    $batch['operations'][] = array('_batch_demo_fill_table_blockedusers', array());

    // Tip the first domino.
    batch_set($batch);
}

function _batch_get_stanza($message_id, $sender, $recipient, $message_content, $subject) {
    $host = EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN;

    $a = array(
        'attr' => array(
            'id' => $message_id,
            'type' => 'chat',
            'to' => $recipient,
            'from' => $sender.'@'.$host
        ),
        'name' => 'message',
        '__array' => array(
            array(
                'attr' => (object) null,
                'name' => 'subject',
                '__array' => array($subject)
            ),
            array(
                'attr' => (object) null,
                'name' => 'body',
                '__array' => array($message_content)
            ),
            array(
                'name' => 'markable',
                'attr' => array(
                    'xmlns' => "urn:xmpp:chat-markers:0"
                )
            )
        )
    );

    $str = json_encode($a);
    return $str;
}

function _batch_get_recipient($mid, $uid) {
    $results = db_query("SELECT * FROM {pm_index} WHERE mid = %d", $mid);

    $recipient = $uid;
    while ($row = db_fetch_object($results)) {
        if($row->recipient != $uid) {
            $recipient = $row->recipient;
        }
    }

    $host = EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN;
    return $recipient.'@'.$host;
}

function generateRandomString($length = 5) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function _batch_demo_fill_table_prosodyarchive(&$context) {

    $limit = 20;

    $offset = isset($context['sandbox']['offset']) ? $context['sandbox']['offset'] : 0;

    $count = db_fetch_object(db_query("SELECT COUNT(*) as count FROM {pm_index}"));
    $results = db_query("SELECT * FROM {pm_index} LIMIT %d OFFSET %d", $limit, $offset);

    $host = EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN;

    while ($row = db_fetch_object($results)) {

        $message = db_fetch_object(db_query("SELECT * FROM {pm_message} WHERE mid = %d", $row->mid));

        $user = $row->recipient;
        $store = 'archive2';
        $when = $message->timestamp;
        $with = _batch_get_recipient($row->mid, $row->recipient);

        if(!isset($context['sandbox']['message_id'])) {
            $message_id = generateRandomString();
            $context['sandbox']['message_id'] = $message_id;
        } else {
            $message_id = $context['sandbox']['message_id'];
            unset($context['sandbox']['message_id']);
        }

        if(!isset($context['sandbox']['stanza'])) {
            $stanza = _batch_get_stanza($message_id, $row->recipient, $with, $message->body, $message->subject);
            $context['sandbox']['stanza'] = $stanza;
        } else {
            $stanza = $context['sandbox']['stanza'];
            unset($context['sandbox']['stanza']);
        }

        db_query("INSERT INTO {prosodyarchive} (`host`, `user`, `store`, `when`, `with`, `stanza`) VALUES ( '%s' , '%s', '%s', '%s', '%s', '%s')", $host, $user, $store, $when, $with, $stanza);
    }

    $context['sandbox']['offset'] = $offset+$limit;

    if($offset >= $count->count) {
        $context['finished'] = 1;
        unset($context['sandbox']['offset']);
    } else {
        $context['finished'] = 0;
    }

}

function _prosodyarchive_get_message_id($row) {
    $json = $row->stanza;
    $obj = json_decode($json);

    return $obj->attr->id;
}

function _batch_demo_fill_table_prosodychatmarkers(&$context) {

    $limit = 20;

    $offset = isset($context['sandbox']['offset']) ? $context['sandbox']['offset'] : 0;

    $count = db_fetch_object(db_query("SELECT COUNT(*) as count FROM {prosodyarchive}"));
    $results = db_query("SELECT * FROM {prosodyarchive} LIMIT %d OFFSET %d", $limit, $offset);

    while ($row = db_fetch_object($results)) {

        $host = $row->host;
        $user = $row->user;
        $store = 'chat_markers';
        $with = $row->with;
        $resource = null;
        $message_id = _prosodyarchive_get_message_id($row);
        $archive_uid = $row->id;
        $markable = 1;
        $mark = 2;
        $stanza = null;

        if(!isset($_SESSION['record'])) {
            $_SESSION['record'] = true;
        } else {
            db_query("INSERT INTO {prosodychatmarkers} (`host`, `user`, `store`, `with`, `resource`, `message_id`, `archive_uid`, `markable`, `mark`) VALUES ( '%s' , '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')", $host, $user, $store, $with, $resource, $message_id, $archive_uid, $markable, $mark);
            unset($_SESSION['record']);
        }

    }

    $context['sandbox']['offset'] = $offset+$limit;

    if($offset >= $count->count) {
        $context['finished'] = 1;
        unset($context['sandbox']['offset']);
    } else {
        $context['finished'] = 0;
    }

}


function _batch_demo_fill_table_blockedusers(&$context) {

    $limit = 20;

    $offset = isset($context['sandbox']['offset']) ? $context['sandbox']['offset'] : 0;

    $count = db_fetch_object(db_query("SELECT COUNT(*) as count FROM {pm_block_user}"));
    $results = db_query("SELECT * FROM {pm_block_user} LIMIT %d OFFSET %d", $limit, $offset);

    $host = EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN;

    while ($row = db_fetch_object($results)) {

        $user = $row->author;
        $store = 'privacy';
        $key = 'lists';
        $type = 'json';

        $result = db_fetch_object(db_query("SELECT value as value FROM {prosody} WHERE `user` = %d AND `store` = 'privacy'", $row->author));

        if(false !== $result) {

            $value = json_decode($result->value, true);

            $value['forbidden']['items'][] = array(
                'message' => false,
                'type' => 'jid',
                'action' => "deny",
                'order' => 4,
                'value' => $row->recipient.'@'.$host,
                'presence-in' => false,
                'iq' => false,
                'presence-out' => false
            );

            $value = json_encode($value);

            db_query("UPDATE {prosody} SET value = '%s' WHERE user = %d AND store = 'privacy'", $value, $row->author);

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
                            'value' => $row->recipient.'@'.$host,
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

    }

    $context['sandbox']['offset'] = $offset+$limit;

    if($offset >= $count->count) {
        $context['finished'] = 1;
        unset($context['sandbox']['offset']);
    } else {
        $context['finished'] = 0;
    }

}

/**
 * The function called when we finish. Displays a success or error message,
 * but could do anything.
 */
function _batch_demo_update_finished($success, $results, $operations) {

    if ($success) {
        $message = t('Migration finished.');
    }
    else {
        $message = t('Finished with error.');
    }
    drupal_set_message($message);
}
?>