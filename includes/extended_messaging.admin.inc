<?php 


function extended_messaging_admin() {

   $form['extended_messaging']['xmpp'] = array(
         '#type' => 'fieldset',
         '#title' => t('XMPP settings'),
   );
   
   $form['extended_messaging']['xmpp']['tigase_help'] = array(
         '#type' => 'fieldset',
         '#title' => t('Tigase config'),
         '#collapsible' => true,
         '#collapsed' =>true,
         '#description' => t('Add to Tigase server init.properties the following lines for this domain').':<br/><code style="white-space:pre-line;">'.
            "--admins = 1@".EXTENDED_MESSAGING_XMPP_DOMAIN."<br/>".
            "--auth-db[".EXTENDED_MESSAGING_XMPP_DOMAIN."]=tigase-custom<br/>".
            "--auth-db-uri[".EXTENDED_MESSAGING_XMPP_DOMAIN."]=jdbc:mysql://&lt;database server&gt;/&lt;database&gt;?user=&lt;db user&gt;&db password=&lt;password&gt;&noAccessToProcedureBodies=true<br>".
            "--virt-hosts = ".EXTENDED_MESSAGING_XMPP_DOMAIN."<br/>
--comp-class-3 = tigase.server.websocket.WebSocketClientConnectionManager<br/>
--comp-name-3 = ws2s</code>"   );
   
   $form['extended_messaging']['xmpp']['prosody_help'] = array(
         '#type' => 'fieldset',
         '#title' => t('Prosody config'),
         '#collapsible' => true,
         '#collapsed' =>true,
         '#description' => t('Add to Prosody server prosody.cfg.lua the following lines for this domain').':<br/><code style="white-space:pre-line;">'.
         'VirtualHost "'.EXTENDED_MESSAGING_XMPP_DOMAIN.'"
               enabled = true -- Remove this line to enable this host
               authentication = "sqlproc" -- be sure to have the mod_auth_sqlproc enabled
               auth_sql_procedures = { auth = "TigUserLoginPlainPw"; }
               admins = { "1@'.EXTENDED_MESSAGING_XMPP_DOMAIN.'" }
               default_storage = "sql" -- Default is "internal"
               sql_manage_tables = true;
               cross_domain_bosh = true;
               cross_domain_websocket = true;

               --storage = "sql"
                     storage = {
                  archive2 = "sql";
               }

               sql = {
                  driver = "MySQL"; -- May also be "MySQL" or "SQLite3" (case sensitive!)
                  database = "&lt;database&gt;"; -- The database name to use. For SQLite3 this the database filename (relative to the data storage directory).
                  host = "&lt;database server&gt;"; -- The address of the database server (delete this line for Postgre
                        username = "&lt;db user&gt;"; -- The username to authenticate to the database
                        password = "&lt;db password&gt;"; -- The password to authenticate to the database
               }

</code>'   );
   
   $form['extended_messaging']['xmpp']['extended_messaging_server'] = array(
         '#type' => 'textfield',
         '#title' => t('XMPP server URL'),
         '#description' => t('Should be a valid HTTP url to BOSH service or directly a websocket url (ws://). If Bosh service provided, will first try if websocket is possible at same host and standard port.'),
         '#default_value' => EXTENDED_MESSAGING_XMPP_SERVER,
   );
   
   $form['extended_messaging']['xmpp']['extended_messaging_ws_url'] = array(
         '#type' => 'textfield',
         '#title' => t('XMPP server URL'),
         '#description' => t('Should be a valid WS url to a websocket url (ws://) including port. (optional)'),
         '#default_value' => EXTENDED_MESSAGING_XMPP_WS_URL,
   );
   
   $form['extended_messaging']['xmpp']['extended_messaging_port'] = array(
         '#type' => 'textfield',
         '#title' => t('XMPP server port'),
         '#default_value' => EXTENDED_MESSAGING_XMPP_PORT,
   );
   
   global $cookie_domain;
   $form['extended_messaging']['xmpp']['extended_messaging_domain'] = array(
         '#type' => 'textfield',
         '#title' => t('XMPP domain'),
         '#default_value' => EXTENDED_MESSAGING_XMPP_DOMAIN == "" ? substr($cookie_domain, 1) : EXTENDED_MESSAGING_XMPP_DOMAIN,
   );
   
   $form['extended_messaging']['xmpp']['extended_messaging_auth_salt'] = array(
         '#type' => 'textfield',
         '#title' => t('XMPP Authentication Salt'),
         '#default_value' => variable_get('extended_messaging_auth_salt', 'None'),
   );

   $privacy_options = array('blacklist'=>t('Blacklist'), 'whitelist'=>t('Whitelist'));
   $form['extended_messaging']['xmpp']['extended_messaging_privacy_mode'] = array(
         '#type' => 'select',
         '#title' => t('XMPP Privacy list mode'),
         '#description' => t("Blacklist means ANYBODY can contact each other, except those in users' blacklists.")."<br/>".t("Whitelist means NOBODY can contact each other, except those in users' whitelists."),
         '#default_value' => EXTENDED_MESSAGING_XMPP_PRICACY_MODE,
         '#options' => $privacy_options
   );


   
   $form = system_settings_form($form);
   
   return $form;

}

?>
