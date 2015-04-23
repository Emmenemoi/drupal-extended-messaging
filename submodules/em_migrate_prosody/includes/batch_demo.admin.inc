<?php
// $Id$

/**
 * @file
 * Contains forms and form handler functions
 */


/**
 * Use Drupal's Form API (FAPI) to wire up buttons to kick off batch operations.
 */
function batch_demo_form(&$form_state) {

    $form['user_batches'] = array(
        '#type' => 'fieldset',
        '#title' => 'User Batches',
        '#description' => 'Run migration operation',
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    $form['user_batches']['batch_add_first_last'] = array(
        '#type' => 'submit',
        '#value' => t('Migrate'),
    );

    return $form;
}

/**
 * Submit handler for batch_demo_form();
 */
function batch_demo_form_submit($form, &$form_state) {

    require_once(drupal_get_path('module', 'em_migrate_prosody') .'/includes/batch_demo.users.inc');

    // Use a switch to catch which button was clicked and route us
    // to the appropriate function.
    switch ($form['#post']['op']) {

        case t("Migrate"):
            batch_demo_first_last(); // Function to kick off a batch API implementation.
            break;

    }

}
?>
