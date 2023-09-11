<?php
require_once 'IAdb.inc.php';

class ia_key_manager { 
//Members
    public $key_largest_day_count = 0;
    public $key_largest_token = 0;
    public function __construct() { 
        $mysql = IA_MySql::get_instance();
        if(!$mysql->connect()) {
          die("Failed establishing connection\n");
          return 0;
        }
    }

    public function internal_activate_token(&$response, $user_id, $token_index, $token_type, $token_expire_type) {
        $mysql = IA_MySql::get_instance();
        $current_date = date("Y-m-d");
        $mysql_rows = $mysql->execute_command("SELECT * FROM `User-Tokens` WHERE `TokenOwnerId`=? AND `IsUsed` = 1;", "i", array($user_id));

        //The amount of days user had on previous token
        $days_left_over = 0;
        foreach($mysql_rows as $mysql_row) {
            if($token_type == $mysql_row['TokenType']) {
                //$response .= "There is a token of the same subscription already active!\n";
                //return 0;

                //Log the old tokens serial and expire date
                $old_token_index = $mysql_row['Index'];
                $old_token_serial = $mysql_row['Token'];
                $old_token_expire_date = $mysql_row['ExpireDate'];
                $old_token_log = $mysql_row['TokenLog'];
                //Delete the old token
                $mysql->execute_command("DELETE FROM `User-Tokens` WHERE (`Index` = ?);", "i", array($old_token_index));

                $token_log_entry = "{". $old_token_serial ." : ". $old_token_expire_date ."}\n" . $old_token_log;
                //Add new value to long
                $mysql->execute_command("UPDATE `User-Tokens` SET `TokenLog` = CONCAT(`TokenLog`, ?) WHERE (`Index` = ?);", "si", array($token_log_entry, $token_index));
                
                if($old_token_expire_date > $current_date)
                {
                    //If there are any days left over
                    $time_left = strtotime($old_token_expire_date) - strtotime($current_date);
                    $days_left_over = floor($time_left / (60 * 60 * 24)); // Convert to days
                }
                
            }
        }

        $subscription_length_in_days = $days_left_over;
        switch($token_expire_type) {
            case 0: // 1 DAY
                $subscription_length_in_days += 1;
            break;
            case 1: // 1 WEEK
                $subscription_length_in_days += 7;
            break;
            case 2: // 1 MONTH
                $subscription_length_in_days += 30;
            break;
            case 3: // 3 Months
                $subscription_length_in_days += 90;
            break;
            case 4: // 6 Months
                $subscription_length_in_days += 180;
            break;
            case 5: // 1 Year
                $subscription_length_in_days += 360;
            break;
            default:
                $response .= "Corrupted token expire date!\n";
                return 0;
            break;
        }
        
        if($subscription_length_in_days > $this->key_largest_day_count) {
            $this->key_largest_day_count = $subscription_length_in_days;
            $this->key_largest_token = $token_index;
        }

        $sqlcommand = "UPDATE `User-Tokens` SET `ExpireDate` = (CURDATE() + INTERVAL ? DAY), `TokenOwnerId` = ?, `IsUsed` = ? WHERE `Index` = ?;";
        $mysql->execute_command($sqlcommand, "iiii", array($subscription_length_in_days, $user_id, 1, $token_index));
    }

    public function renew_key(&$response, $user_id, $Token) {
        if($user_id == -1) {
            $response .= "userid invalid!\n";
            return 0;
        }

        //We call this here in order to delete old tokens that have expired
        $ia_xf = new ia_xenforo_interface();
        $ia_xf->xenforo_has_active_subscriptions($user_id, $response);

        $mysql = IA_MySql::get_instance();
        //Check if token exists
        $mysql_rows = $mysql->execute_command("SELECT * FROM `User-Tokens` WHERE `Token`=?;", "s", array($Token));
        if(count($mysql_rows) <= 0) {
            $response .= "No token found!\n";
            return 0;
        }
        if($mysql_rows[0]['IsUsed'] == 1) {
            $response .= "Token already used!\n";
            return 0;
        }

        $current_date = date("Y-m-d");

        $token_index = $mysql_rows[0]['Index'];
        $token_value = $mysql_rows[0]['Token'];
        $token_type = $mysql_rows[0]['TokenType'];
        $token_expire_type = $mysql_rows[0]['SubscriptionLength'];
        $token_addons = $mysql_rows[0]['KeyAddons'];

        $this->internal_activate_token($response, $user_id, $token_index, $token_type, $token_expire_type);

        //KEY ADDONS
        if(strlen($token_addons) > 0) {
            //That means this key has additional goodies we should activate
            foreach (explode(',', $token_addons) as $addon_token_type) {
                if(is_numeric($addon_token_type)) {
               //Create a new key
               $mysql->execute_command("INSERT INTO `User-Tokens` (`Token`, `TokenType`, `SubscriptionLength`, `IsUsed`, `TokenOwner`, `ExpireDate`) VALUES (?, ?, ?, '0', '', '');", "sii", array($token_value, $addon_token_type, $token_expire_type));
               //Get the key index
               $mysql_rows = $mysql->execute_command("SELECT * FROM `User-Tokens` WHERE `Token`=? AND `TokenType`=?;", "si", array($token_value, $addon_token_type));
               if(count($mysql_rows) <= 0) {
                $response .= "Failed fetching joint token index\n";
                return 0;
              }
               $addon_token_index = $mysql_rows[0]['Index'];

              $this->internal_activate_token($response, $user_id, $addon_token_index, $addon_token_type, $token_expire_type);

                }
            }
        }

  
        return 1;
    }
  
}


?>