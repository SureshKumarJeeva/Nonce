<?php

/**
 * Nonce
 * A class consists of handling requests related to creating, verifying Nonce value for an application
 * This class is created in order to provide a functionality similar to nonce functions available for WordPress applications. 
 *
 * PHP version 5.4
 * 
 * @author Suresh Kumar
 * 
 */
class Nonce {
    
    /*
     * Number of seconds in a day 
     */
    private $nonce_life = 86400;
    
    /*
     * Constructor to declare and define attributes of Nonce
     */
    function __construct() {
        
    }

    /*
     * Create a token using unique user, session, context constant
     * @param string $userID unique user id of current user
     * @param string $context_const String value to be used during creation of nonce value. This same String value need to be passed on while verifying the nonce value.
     * $param string $userToken [optional] User token maintained in cookie for a particular user by the application
     * @return the token
     */

    public function nonce_create($userID, $context_const, $userToken = '') {
        $i  = ceil( time() / ( $this->nonce_life / 2 ) );
        return substr(_hash_hmac('md5', $i . "|" . $userID . "|" . $context_const . "|" . $userToken, $userToken), -12, 10);
    }

    /*
     * Create a hash value with passed arguments
     * @param string $algo md5 or sha1 algorithm 
     * @param string $data data with which nonce value is generated.
     * $param string $context_const String value to be used during creation of nonce value. This same String value need to be passed on while verifying the nonce value.
     * $raw_output boolean does the token need to be retrned in raw mode or in binary format.
     * @return the token
     */
    private function _hash_hmac($algo, $data, $key, $raw_output = false) {
        $packs = array(
            'md5' => 'H32',
            'sha1' => 'H40',
        );

        if (!isset($packs[$algo])) {
            return false;
        }

        $pack = $packs[$algo];

        if (strlen($key) > 64) {
            $key = pack($pack, $algo($key));
        }

        $key = str_pad($key, 64, chr(0));

        $ipad = ( substr($key, 0, 64) ^ str_repeat(chr(0x36), 64) );
        $opad = ( substr($key, 0, 64) ^ str_repeat(chr(0x5C), 64) );

        $hmac = $algo($opad . pack($pack, $algo($ipad . $data)));

        if ($raw_output) {
            return pack($pack, $hmac);
        }
        return $hmac;
    }

}
