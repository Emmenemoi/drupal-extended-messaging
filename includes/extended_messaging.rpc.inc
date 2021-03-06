<?php 

/**
 * REST JSON service at url: <base>/messaging/rpc/<subject>
 * subject: can be node, user
 * 
 * parameters are passed in messaging_rpc_cmd param through POST in a JSON object 
 * messaging_rpc_cmd: array of cmd
 * [
 *    {
 *     cmd: function name (for the moment: load
 *     args: arguments
 *     } ,
 * ]
 * 
 * @param unknown $subject
 */

function extended_messaging_rpc($subject) {
   if (function_exists( 'drupal_add_http_header')) {
       drupal_add_http_header('Content-Type','text/javascript');  
       drupal_add_http_header('Cache-Control','no-cache');  
       drupal_add_http_header('Pragma', 'no-cache');
       drupal_add_http_header('Access-Control-Allow-Origin', '"*" IS_CORS');
       drupal_add_http_header('Access-Control-Allow-Methods', 'PUT, GET, POST, DELETE, OPTIONS');
       drupal_add_http_header('Access-Control-Allow-Headers', 'x-requested-with');
   } else {
       drupal_set_header('Content-Type: text/javascript');  
       drupal_set_header('Cache-Control: no-cache');  
       drupal_set_header('Pragma: no-cache');
       drupal_set_header('Access-Control-Allow-Origin: "*" IS_CORS');
       drupal_set_header('Access-Control-Allow-Methods: PUT, GET, POST, DELETE, OPTIONS');
       drupal_set_header('Access-Control-Allow-Headers: x-requested-with');
   }
   
   static $return_filter;
   static $functions;
   if ( !isset($return_filter) || !isset($functions) ) {
      $return_filter = array('uid'=>0, 'nid'=>0, 'created'=>0, 'updated'=>0, 'title'=>0, 'name'=>0, 'body'=>0, 'jid'=>0);
      $functions = array('load'=>'%subject_load', 'set'=>'%subject_set');
      drupal_alter('em_rpc_filter', $return_filter);
      drupal_alter('em_rpc_functions', $functions);      
   }
   
   //$request = json_decode($_REQUEST['messaging_rpc_cmd']);
   $rawPOST = file_get_contents('php://input'); 
   $request = json_decode($rawPOST);
   $result = array();
   //print_r($request);
   if ( isset($request->messaging_rpc_cmd) && is_array($request->messaging_rpc_cmd)) {
      $rest = $request->messaging_rpc_cmd;
      foreach($rest as $command) {
         $function = strtr($functions[$command->command], array('%subject'=> $subject));
         if (function_exists($function)) {
            $raw = (array) ( is_array($command->arguments) ? call_user_func_array($function, $command->arguments) : call_user_func($function, $command->arguments) );
            // clean. always return a value to be in line with cmd index
            //print_r($raw);
            $result[] = (object) (is_array($raw) ? array_intersect_key($raw, $return_filter ) : false);
         }
      }

   }
   print json_encode($result);
   module_invoke_all('exit');exit();
}

?>