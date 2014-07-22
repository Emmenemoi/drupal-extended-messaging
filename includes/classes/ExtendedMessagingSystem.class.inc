<?php

module_load_include('class.inc', 'extended_messaging', 'includes/classes/ExtendedMessagingBase');

class ExtendedMessagingSystem extends ExtendedMessagingBase {
   
   public function User() {
      if ( empty( $this->xmppuser ) ) {
         $user = new stdClass();
         $user->uid = 0;
         $user->name = 'no-reply';
         $this->xmppuser = new XMPPUser($user);
      }
      
      return $this->xmppuser;
   }
}