<?php 


function extended_messaging_admin() {

   $form['extended_messaging']['xmpp'] = array(
         '#type' => 'fieldset',
         '#title' => t('XMPP settings'),
         '#description' => t('Add to Tigase server init.properties the following lines for this domain').':<br/><code>'.
            "--admins = 1@".EXTENDED_MESSAGING_XMPP_DOMAIN."<br/>".
            "--auth-db[".EXTENDED_MESSAGING_XMPP_DOMAIN."]=tigase-custom<br/>".
            "--auth-db-uri[".EXTENDED_MESSAGING_XMPP_DOMAIN."]=jdbc:mysql://&lt;database server&gt;/&lt;database&gt;?user=&lt;db user&gt;&db password=&lt;password&gt;&noAccessToProcedureBodies=true<br>".
            "--virt-hosts = ".EXTENDED_MESSAGING_XMPP_DOMAIN."<br/>
--comp-class-3 = tigase.server.websocket.WebSocketClientConnectionManager<br/>
--comp-name-3 = ws2s</code>"
   );
   
   $form['extended_messaging']['xmpp']['extended_messaging_server'] = array(
         '#type' => 'textfield',
         '#title' => t('XMPP server URL'),
         '#description' => t('Should be a valid HTTP url to BOSH service or directly a websocket url (ws://). If Bosh service provided, will first try if websocket is possible at same host and standard port.'),
         '#default_value' => EXTENDED_MESSAGING_XMPP_SERVER,
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
         '#default_value' => variable_get('extended_messaging_auth_salt', None),
   );
   
   $form = system_settings_form($form);
   
   return $form;

}

?>