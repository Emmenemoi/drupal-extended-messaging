<?php

class XMPPUser {
   
   public $nickname;
   public $uid;
   
   // $user is UID or User Object or JID
   function __construct($user) {
      if (is_string($user) && ($pos=strpos($user, "@") ) !== false ) {
         $user = substr($user, 0, $pos);
      }
      if (is_numeric($user)) {
         $user = user_load($user);
      }
      // $user is now User object for sure
      $this->nickname = XMPPUser::filterNick($user->name);
      $this->uid = is_numeric($user) ? $user : $user->uid;
   }
   
   function JID() {
      return XMPPUser::getBareJID($this->uid)."/".$this->nickname;
   }
   
   function BareJID(){
      return XMPPUser::getBareJID($this->uid);
   }
   
   static function getBareJID($user) {
      $id = is_numeric($user) ? $user : $user->uid;
      return $id."@".EXTENDED_MESSAGING_XMPP_DOMAIN;  
   }
   
   private static function filterNick($nick) {
      return str_replace(array('@', ':', '\'', '"', '>', '<', '&'), '', $nick);
   }
}