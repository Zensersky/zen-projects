<?php
class sellix_handler { 

//Functions
public function verify_header() {
    $payload = file_get_contents('php://input');
    $secret = 'yoursecrethere'; 
    $header_signature = $_SERVER['HTTP_X_SELLIX_SIGNATURE'];
    $signature = hash_hmac('sha512', $payload, $secret);
    if (hash_equals($signature, $header_signature)) {
       
        return 1;
    } else {
        return 0;
    }
}

public function get_sellix_json_data(&$payload) {
    return json_decode($payload, false);
}

public function get_token(&$json_data) {
    if (empty($json_data->data->serials)) {
        return NULL;
    }
    //It can return with \r or \n in the end so we better check and remove it
    $serial_unsafe = $json_data->data->serials[0];

    $trailingChars = array("\r", "\n");
    while (in_array(substr($serial_unsafe, -1), $trailingChars)) {
        $serial_unsafe = substr($serial_unsafe, 0, -1);
      }

    return $serial_unsafe;
}

public function get_sellix_addon_ids(&$json_data) {
    $data_addons = $json_data->data->addons;
    if (empty($data_addons)) {
        return NULL;
    }

    $uniqids = array(); // initialize empty array
    foreach ($data_addons as $addon) {
     foreach ($addon as $item) {
      $uniqids[] = $item->uniqid; // add uniqid to array
     }
    }
    return $uniqids;
}

public function sellix_addon_to_index($addon_id) {
    switch($addon_id) {
        case '64079f7467e9': // test addon
            return array(2,3);
            break;
        case '6408541dfd5a': 
            return array(2,3);
            break;
        case '64850fae3f48': 
            return array(2,3);
            break;
        case '64071945e9aa': 
            return array(2,3);
            break;
        default:
        return -1;
        break;
    }
}

}

?>