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

    const MINUTE_IN_SECONDS = 60;
    const HOUR_IN_SECONDS = self::MINUTE_IN_SECONDS * 60;
    const DAY_IN_SECONDS = self::HOUR_IN_SECONDS * 24;
    const WEEK_IN_SECONDS = self::DAY_IN_SECONDS * 7;
    const MONTH_IN_SECONDS = self::DAY_IN_SECONDS * 30;
    const YEAR_IN_SECONDS = self::DAY_IN_SECONDS * 365;

    /*
     * Constructor to declare and define attributes of Nonce
     * @param $nonceLife gets nonce life time to be declared initially. By default nonce life is valid for half of a day.
     */

    function __construct($nonceLife = self::DAY_IN_SECONDS) {
        $this->nonce_life = $nonceLife;
    }

    /*
     * Create a token using unique user, session, context constant
     * @param string $userID unique user id of current user
     * @param string $context_const String value to be used during creation of nonce value. This same String value need to be passed on while verifying the nonce value.
     * $param string $userToken [optional] User token maintained in cookie for a particular user by the application
     * @return the token
     */

    public function nonce_create($userID, $context_const, $userToken = '') {
        $i = ceil(time() / ( $this->nonce_life / 2 ));
        return substr($this->_hash_hmac('md5', $i . "|" . $userID . "|" . $context_const . "|" . $userToken, $userToken), -12, 10);
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

    /*
     * Verify if a token is valid within the time limit and the time limit is assigned while instantiating this class
     * @param string $userID unique user id of current user
     * @param string $context_const String value used during creation of nonce value.
     * @param string $nonce the token that need to be verified against the time duration.
     * $param string $userToken [optional] User token maintained in cookie for a particular user by the application
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
     *                             1st half of time limit, 2 if the nonce is valid and generated between second half of the time limit
     */

    public function nonce_verify($userID, $context_const, $nonce, $userToken = '') {
        $nonce = (string) $nonce;
        if (empty($nonce)) {
            return false;
        }
        $i = ceil(time() / ( $this->nonce_life / 2 ));
        // Nonce generated 0-12 hours ago
        $expected = substr($this->_hash_hmac('md5', $i . "|" . $userID . "|" . $context_const . "|" . $userToken, $userToken), -12, 10);
        if (hash_equals($expected, $nonce)) {
            return 1;
        }
        // Nonce generated 12-24 hours ago
        $expected = substr($this->_hash_hmac('md5', ($i-1) . "|" . $userID . "|" . $context_const . "|" . $userToken, $userToken), -12, 10);
        if (hash_equals($expected, $nonce)) {
            return 2;
        }
        return false;
    }

    /**
     * Timing attack safe string comparison
     *
     * Compares two strings using the same time whether they're equal or not.
     *
     * This function was added in PHP 5.6.
     *
     * Note: It can leak the length of a string when arguments of differing length are supplied.
     *
     * @param string $a Expected string.
     * @param string $b Actual, user supplied, string.
     * @return bool Whether strings are equal.
     */
    function hash_equals($a, $b) {
        $a_length = strlen($a);
        if ($a_length !== strlen($b)) {
            return false;
        }
        $result = 0;
        // Do not attempt to "optimize" this.
        for ($i = 0; $i < $a_length; $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $result === 0;
    }

}
