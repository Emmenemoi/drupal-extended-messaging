<?php 
function em_messagesui_chat_title(){
   return "Private Messages";
}


function em_messagesui_chat_page() {
   
   extended_messaging_include_settings();
   
   return "<div id='extended-messaging-chat-page'>
             <noscript>
               <div style='width: 22em; position: absolute; left: 50%; margin-left: -11em; color: red; background-color: white; border: 1px solid red; padding: 4px; font-family: sans-serif'>
                 Your web browser must have JavaScript enabled
                 in order for this application to display correctly.
               </div>
             </noscript>
         </div>";
}



?>