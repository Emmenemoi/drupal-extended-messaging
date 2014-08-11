<?php

module_load_include('class.inc', 'extended_messaging', 'includes/classes/ExtendedMessagingBase');

class ExtendedMessagingUser extends ExtendedMessagingBase {
   
   public static function User() {
      if ( empty( $this->xmppuser ) ) {
         $user = 1;
         $this->xmppuser = new XMPPUser($user);
      }
      
      return $this->xmppuser;
   }

}