<?php

class XMPPRoom {
   
   public $name;
   private $owner;
   private $owner_uid;
   
   // $name is name or owner UID or User Object
   function __construct($name) {
      if (is_string($name) && ($pos=strpos($name, "@") ) !== false ) {
         $name = substr($name, 0, $pos);
      }
      if (is_numeric($name)) {
         $this->owner_uid = $name;
      }
      if (is_object($name)) {
         $this->owner = $name;
         $this->owner_uid = $name->uid;
      }

      $this->name = is_numeric($this->owner_uid) ? $this->owner_uid : $name;
   }
   
   function getOwner() {
      if (!isset($this->owner)) {
         $this->owner = user_load($this->owner_uid);
      }

      return $this->owner;
   }

   function JID() {
      return XMPPRoom::getBareJID($this->name);//."/".$this->nickname;
   }
   
   function BareJID(){
      return XMPPRoom::getBareJID($this->name);
   }
   
   static function getBareJID($name) {
      return $name."@".EXTENDED_MESSAGING_XMPP_MUC_DOMAIN;  
   }
   
   private static function filterNick($nick) {
      return str_replace(array('@', ':', '\'', '"', '>', '<', '&'), '', $nick);
   }
}