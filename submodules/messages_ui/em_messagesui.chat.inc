<?php 
function em_messagesui_chat_title(){
   return "Private Messages";
}


function em_messagesui_chat_page() {
   
   extended_messaging_include_settings();
   $module_path = drupal_get_path('module', 'em_messagesui');
   //$script = url($module_path."/gwt_extended_messaging/gwt_extended_messaging.nocache.js")."?".rand(0,10000);
   drupal_add_js($module_path."/gwt_extended_messaging/gwt_extended_messaging.nocache.js", 'module', 'header', false, TRUE, FALSE);
   
   return "<div id='extended-messaging-chat-page' style='width:100%;height:600px;'></div>
             <noscript>
               <div style='width: 22em; position: absolute; left: 50%; margin-left: -11em; color: red; background-color: white; border: 1px solid red; padding: 4px; font-family: sans-serif'>
                 Your web browser must have JavaScript enabled
                 in order for this application to display correctly.
               </div>
             </noscript>";
}



?>