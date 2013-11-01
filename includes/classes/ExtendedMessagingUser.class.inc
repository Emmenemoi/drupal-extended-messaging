<?php

module_load_include('class.inc', 'extended_messaging', 'includes/classes/ExtendedMessagingBase');

class ExtendedMessagingUser extends ExtendedMessagingBase {
   
   public function User() {
      if ( empty( $this->xmppuser ) ) {
         global $user;
         $this->xmppuser = new XMPPUser($user);
      }
      
      return $this->xmppuser;
   }
}