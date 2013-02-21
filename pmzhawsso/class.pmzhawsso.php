<?php
/**
 * The Windows IIS SSO class
 *
 * @author Philipp Hungerbühler
 * @package plugins.pmzhawsso
 * @copyright Copyright (C) 2012 ZHAW.
 */

G::LoadClass('plugin');

class pmzhawssoClass extends PMPlugin {

    /**
     * Contructor of the class
     * @return void
     */
    public function __construct() {
        set_include_path(PATH_PLUGINS . 'pmzhawsso' . PATH_SEPARATOR . get_include_path());
    }

    /**
     * The generic setup function
     *
     * @return void
     */
    public function setup() {
    }

    /**
     * Add a line in the log
     *
     * @author Philipp Hungerbühler
     * @param String $text The text to save in the log
     */
    public static function log($text) {
        $fpt = fopen(PATH_DATA . 'log/pmzhawsso.log', 'a');
        fwrite($fpt, sprintf("%s %s %s %s\n", date('Y-m-d H:i:s'), getenv('REMOTE_ADDR'), SYS_SYS, $text));
        fclose($fpt);
    }

    public function singleSignOn() {
        global $RBAC;
        //$this->log('SSO trigger start');
		
        $server = $_SERVER['SERVER_SOFTWARE'];
        $webserver = explode("/", $server);
        if (!is_array($webserver) || (is_array($webserver) && ($webserver[0] != 'Microsoft-IIS'))){
            return false;
        }
        
        $RBAC =& RBAC::getSingleton();
        $RBAC->initRBAC();
        
        // We actually should already be authenticated
        $userFull = $_SERVER['REMOTE_USER'];
        $userPN = explode("\\", $userFull);
        if (is_array($userPN)){
            $user = $userPN[1];
        } else {
			$user = $userFull;
		}
		
        //$user = 'hune';
        if(empty($user) || $user == '')
        {
            $RBAC->singleSignOn = false;            
            return false;   
        } 

        // If the user exists, the VerifyUser function will return the user properties
        $resVerifyUser = $RBAC->verifyUser($user);
        $RBAC->singleSignOn = true;                        

        $this->log('SSO trigger user name: ' . $user);
        
        if ($resVerifyUser == 0) {
            // Here we are checking if the automatic user Register is enabled, ioc return -1
            $res = $RBAC->checkAutomaticRegister($user, 'fakepassword');
            if ($res === -1) {
                return false; // No sucessful auto register, skipping the auto register and back to normal login form
            }
            $RBAC->verifyUser($user);
        }
        if (!isset($RBAC->userObj->fields['USR_STATUS']) || $RBAC->userObj->fields['USR_STATUS'] == 0) {
            $this->log('Single Sign On failed for user ' . $user);
            return false;
        }

		$this->log('Single Sign On successful for user ' . $user);
        return true;
    }
}