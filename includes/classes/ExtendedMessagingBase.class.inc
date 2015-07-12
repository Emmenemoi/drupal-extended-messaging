<?php

module_load_include('class.inc', 'extended_messaging', 'includes/classes/XMPPUser');

abstract class ExtendedMessagingBase {
   /**
    * @var XMPPUser
    */
   protected $xmppuser;   
   protected $auth;
   
   const      TOKEN_PREFIX = "TOKEN|";
    
   abstract public function User();
   
   public function BareJID() {
      return $this->User()->BareJID();
   }
   
   public function Auth() {
      if ( empty($this->auth ) ) {
         $user = static::User();
         $this->auth = self::getAuth($user);
      }
      return $this->auth;
   }
   
   public function Nick() {
      return $this->User()->nickname;
   }

   /**
    * @param XMPPUser $user
    * @return string
    */
   public static function getAuth(XMPPUser $user) {
         $salt = variable_get('extended_messaging_auth_salt', 'None');
         $timestamp = time();
         $login = $user->BareJID();
         $token = hash('sha256', $login . $timestamp . $salt);
         /*$signature = array('volatil', $login, $timestamp, $token);*/
         $signature =self::TOKEN_PREFIX. $token;
         db_query("INSERT INTO {extended_messaging_sessions} (uid, token, created) VALUES (%d, '%s', UNIX_TIMESTAMP() )", $user->uid, $token);
         return $signature;
   }
   
   public static function instance(){
      static $instance;
      if ( empty( $instance) ) {
         $instance = new static();
      }
      
      return $instance;
   }
}
