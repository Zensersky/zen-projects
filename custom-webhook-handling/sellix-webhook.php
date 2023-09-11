<?php
require_once('sellix-webhook.inc.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/scripts/IAdb.inc.php');

  $payload = file_get_contents('php://input');
  $sellix_interface = new sellix_handler();
  if ($sellix_interface->verify_header() == 1) {
    // handle valid webhook
    echo "Signature valid!\n";

    $json_data = $sellix_interface->get_sellix_json_data($payload);
    
    if ($json_data === null) {
      $json_error = json_last_error_msg();
      error_log("JSON decoding error: $json_error");
      return;
    }

    echo "event: " . $json_data->event . " \n";
    //var_dump($json_data);
    if ($json_data->event == 'order:paid') {
      
      $sellix_token = $sellix_interface->get_token($json_data);
      $sellix_addon_ids = $sellix_interface->get_sellix_addon_ids($json_data);


      if(empty($sellix_token)) {
        echo "Failed locating serial inside json data!\n";
        http_response_code(200);
        return;
      }

      echo "Token Serial : " . $sellix_token . " \n";
      

      if(count($sellix_addon_ids) <= 0) {
        echo "There were no valid addons for this sellix request! 1\n";
        http_response_code(200);
        return;
      }

      //Connect to our database
      $mysql = IA_MySql::get_instance();
      if(!$mysql->connect()) {
        echo "Failed establishing connection\n";
        http_response_code(200);
        return 0;
      }
      //Convert the uniqueIDs to tokens with indexes
      $token_addons = array();
      foreach($sellix_addon_ids as $addon_unique_id) {
        echo "Token addon id : " . $addon_unique_id . " \n";
        $addon_binary_index = $sellix_interface->sellix_addon_to_index($addon_unique_id);
        if(is_array($addon_binary_index)) {
          $token_addons = array_merge($token_addons, $addon_binary_index);
        }
        elseif($addon_binary_index != -1) {
          $token_addons[] = $addon_binary_index;
        }
      }

      if(count($token_addons) <= 0) {
        echo "There were no valid addons for this sellix request 2!\n";
        http_response_code(200);
        return;
      }

      $str_token_extra_addons = implode(',', $token_addons);
      $mysql_rows = $mysql->execute_command("SELECT * FROM `Tokens` WHERE `Token`=?;", "s", array($sellix_token));
      if(count($mysql_rows) <= 0) {
        echo "Failed locating serial in database\n";
        http_response_code(200);
        return 0;
      }
      $token_index = $mysql_rows[0]['Index'];
      $mysql->execute_command("UPDATE `Tokens` SET `KeyAddons` = ? WHERE (`Index` = ?);", "si", array($str_token_extra_addons, $token_index));
      echo "Updated the key addons for token!\n";
    }
    echo "Webhook processed succesfully!\n";
    http_response_code(200);
  } else {
      echo "Signature not valid!\n";
      http_response_code(401);
  }
?>
