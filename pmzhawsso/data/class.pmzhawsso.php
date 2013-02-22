<?php
/**
 * The Windows SSO class for the RBAC
 *
 * @author Philipp Hungerbühler
 * @package plugins.pmzhawsso
 * @copyright Copyright (C) 2004 - 2011 Colosa Inc.
 */

class pmzhawsso {
    /**
     * The authsource id
     * @var String
     */
    var $sAuthSource = '';

    /**
     * a local variable to store connection with LDAP, and avoid multiple bindings
     * @var String
     */
    var $oLink = NULL;

    /**
     * The users information array
     * @var Array
     */
    var $aUserInfo = array();

    /**
     * System information
     * @var String
     */
    var $sSystem = '';

    /**
     * Object where an rbac instance is set
     * @var Object
     */
    static private $instance = NULL;
    
    /**
     * The constructor method, stores the connection to the Active Directory
     * using the plexcel configuration, also stores the base DN
     *
     * @return void
     */
    public function __construct() {
    }

    /**
     * Add a line in the log
     *
     * @author Philipp Hungerbühler
     * @param String $text The text to save in the log
     * @return void
     */
    function log($text) {
        if (!class_exists('pmzhawssoClass')) {
            require_once PATH_PLUGINS . 'pmzhawsso/class.pmzhawsso.php';
        }
        pmzhawssoClass::log($text);
    }    
    
    /**
     * This method gets the singleton Rbac instance.
     * @return Object instance of the rbac class
     */
    function &getSingleton() {
        if (self::$instance == NULL) {
            self::$instance = new RBAC();
        }
        return self::$instance;
    }  

    /**
     * Creates a ldap connection
     * 
     * @param Array $aAuthSource The authentication source data
     * @return Object The link object
     */
    function ldapConnection ($aAuthSource) {
        $pass = explode("_",$aAuthSource['AUTH_SOURCE_PASSWORD']);
        foreach($pass as $index => $value) {
            if($value == '2NnV3ujj3w'){
                $aAuthSource['AUTH_SOURCE_PASSWORD'] = G::decrypt($pass[0],$aAuthSource['AUTH_SOURCE_SERVER_NAME']);
            }
        }
		
        $oLink = @ldap_connect($aAuthSource['AUTH_SOURCE_SERVER_NAME'], $aAuthSource['AUTH_SOURCE_PORT']);
        $ldapServer = $aAuthSource['AUTH_SOURCE_SERVER_NAME'] . ":" . $aAuthSource['AUTH_SOURCE_PORT'] ;
        @ldap_set_option($oLink, LDAP_OPT_PROTOCOL_VERSION, $aAuthSource['AUTH_SOURCE_VERSION']);
        @ldap_set_option($oLink, LDAP_OPT_REFERRALS, 0);

        if (isset($aAuthSource['AUTH_SOURCE_ENABLED_TLS']) && $aAuthSource['AUTH_SOURCE_ENABLED_TLS']) {
            @ldap_start_tls($oLink);
            $ldapServer = "TLS " . $ldapServer;
        }
        if ($aAuthSource['AUTH_ANONYMOUS'] == '1') {
            $bBind = @ldap_bind($oLink);
            //$this->log ("class.pmzhawsso.php: Bind $ldapServer like anonymous user" );
        }
        else {
            $bBind = @ldap_bind($oLink, $aAuthSource['AUTH_SOURCE_SEARCH_USER'], $aAuthSource['AUTH_SOURCE_PASSWORD']);
            //$this->log ("class.pmzhawsso.php: Bind $ldapServer with user " . $aAuthSource['AUTH_SOURCE_SEARCH_USER'] );
        }

        if ( !$bBind ) {
            $this->log('class.pmzhawsso.php: Unable to bind to server : ' . $aAuthSource['AUTH_SOURCE_SERVER_NAME'] . ' on port ' . $aAuthSource['AUTH_SOURCE_PORT']);
            return null;
        }
        return $oLink;
    }  

    /**
     * Get all ldap attributes for a given entry
     *
     * @param Object $oLink Ldap link to use
     * @param Object $oEntry Entry object
     * @return Object Ldap element
     */    
    function getLdapAttributes ( $oLink, $oEntry ) {
        $aAttrib['dn'] = @ldap_get_dn($oLink, $oEntry);
        $aAttr = @ldap_get_attributes($oLink, $oEntry);
        for ( $iAtt = 0 ; $iAtt < $aAttr['count']; $iAtt++ ) {
            switch ( $aAttr[ $aAttr[$iAtt] ]['count'] ) {
                case 0: $aAttrib[ strtolower($aAttr[$iAtt]) ]= '';
                    break;
                case 1: $aAttrib[ strtolower($aAttr[$iAtt]) ]= $aAttr[ $aAttr[$iAtt] ][0];
                    break;
                default:
                    $aAttrib[ strtolower($aAttr[$iAtt]) ]= $aAttr[ $aAttr[$iAtt] ];
                    unset( $aAttrib[ $aAttr[$iAtt] ]['count'] );
                    break;
            }
        }
        return $aAttrib;
    }     
    
    /**
     * This method authentifies if a user has the RBAC_user privileges
     * also verifies if the user has the rights to start an application
     *
     * @author Fernando Ontiveros Lira <fernando@colosa.com>
     * @access public

     * @param  string $username UserId  (user login)
     * @param  string $password Password
     * @return
     *   1: return = true
     *  -1: user doesn't exists / no existe usuario
     *  -2: wrong password / password errado
     *  -3: inactive user / usuario inactivo
     *  -4: user due date / usuario vencido
     *  -5: connection error
     *  n : user uid / uid de usuario
     */
    public function VerifyLogin($strUser, $strPass) {
        $return = 1;
		//$this->log('class.pmzhawsso.php: Enter VerifyLogin');

        try {        
            // Sometimes the username is an array, but we are using only the first item
            if (is_array($strUser)) {
                $username = trim($strUser[0]);
            }
            else {
                $username = trim($strUser);
            }

			$this->log('class.pmzhawsso.php: User: '.$username );
            // If user is empty we return with error
            if (strlen($username) == 0) {
                $return = -1;            
            } else {
				$this->log('class.pmzhawsso.php: Remote user: ' . ($_SERVER["REMOTE_USER"] != ''?$_SERVER["REMOTE_USER"]:'not defined'));
                if (!isset( $_SERVER["REMOTE_USER"]) || ($_SERVER["REMOTE_USER"] == '')){
                    // Somehow integrated authentication did not work, check with password
                    $RBAC = RBAC::getSingleton();
                    if ($RBAC->authSourcesObj == NULL){
                        $RBAC->authSourcesObj = new AuthenticationSource();
                    }
                    $aAuthSource  = $RBAC->authSourcesObj->load($this->sAuthSource);

                    if ($this->oLink == NULL) {
                        $oLink = $this->ldapConnection($aAuthSource);
                        $this->oLink = $oLink;
                    }
                    else
                        $oLink = $this->oLink;        
                
                    $validUserPass = @ldap_bind($oLink, $username, $strPass );
					$this->log('class.pmzhawsso.php: Normal login: '.$validUserPass);
                } else {
                    $validUserPass = true;
					$this->log('class.pmzhawsso.php: SSO login: '.$validUserPass);
                }
        
                if ($validUserPass) {
                    // check if the dn in the database record matches with the dn for the ldap account
                    $userDN             = ldap_explode_dn($username,1);
                    $userDNArray        = $this->custom_ldap_explode_dn($username);
                    $userDNIdentifier   = explode('=',$userDNArray[0]);
                    $verifiedUser       = $this->searchUserByUid($userDN[0]);

					//$this->log('class.pmzhawsso.php: Check DB: '.print_r($verifiedUser,true));
                    if ($verifiedUser && is_array($verifiedUser)){
                        if ( $verifiedUser['sDN'] != $username && $verifiedUser['sDN'] != null ){
                            // if not Equals for that user uid
                            if (!class_exists('RbacUsers')) {
                                require_once(PATH_RBAC.'model/RbacUsers.php');
                            }

                            $con = Propel::getConnection(RbacUsersPeer::DATABASE_NAME);
                            // select set
                            $c1 = new Criteria('rbac');
                            $c1->add(RbacUsersPeer::USR_AUTH_USER_DN, $username);
                            // update set
                            $c2 = new Criteria('rbac');
                            $c2->add(RbacUsersPeer::USR_AUTH_USER_DN, $verifiedUser['sDN']);

                            BasePeer::doUpdate($c1, $c2, $con);
                        }            
                    } else {
                        $return = -1;
                    }
                }
            }
        }
        catch (Exception $error) {
            $return = -5;
        }

		// Make sure, that we return a bool value
        if ( $return == 1 ) {
            $this->log("Sucessful login user " . $verifiedUser['sDN']);
			return TRUE;
		}
        else {
            $this->log("Failure authentication for user $strUser ");
			return FALSE;
		}
    } 
	
    /**
     * Additional handling of DN
     *
     * @param  string Source DN
     * @return string Adapted DN
     */
    function custom_ldap_explode_dn($dn) {
        $dn = trim($dn, ',');
        $result = ldap_explode_dn($dn, 0);
        if (is_array($result)) {
            unset($result['count']);
            foreach($result as $key => $value){
                $result[$key] = addcslashes(preg_replace("/\\\([0-9A-Fa-f]{2})/e", "''.chr(hexdec('\\1')).''", $value), '<>,"');
            }
        }
        return $result;
    }

    /**
     * This method search a user in the active directory by username
     *
     * @param String $sKeyword The keyword in order to match the record with the identifier attribute
     * @param String $identifier id identifier, this parameter is optional
     * @return mixed if the user has been found or not
     */
    public function searchUserByUid($username) {
        try {
            // Sometimes the username is an array, but we are using only the first item
            if (is_array($username)) {
                $username = trim($username[0]);
            }
            else {
                $username = trim($username);
            }
            $results = $this->searchUsers($username, true);
            if (is_array($results) == false || count($results) == 0) {
                $this->log("class.pmzhawsso.php: No results with filter: $username. Is AD configuration correct?");
                return null;
            }
            if (count($results) > 1) {
                $this->log("class.pmzhawsso.php: Too many results (expecting only one row) for search with filter: $username");
                return null;
            }
            return $results[0];
        }
        catch (Exception $error) {
            throw $error;
        }
    }    

    /**
     * Search accounts using a filter in the Active Directory
     *
     * @param String The keywords to use
     * @return Array The objects found
     */
    public function searchUsers($keyword, $exacte = false) {
        $sKeyword  = trim($keyword);
        $objects = array();
        
        $RBAC = RBAC::getSingleton();
        if ($RBAC->authSourcesObj == NULL){
            $RBAC->authSourcesObj = new AuthenticationSource();
        }
        $aAuthSource  = $RBAC->authSourcesObj->load($this->sAuthSource);

        if ($this->oLink == NULL) {
            $oLink = $this->ldapConnection($aAuthSource);
            $this->oLink = $oLink;
        }
        else
            $oLink = $this->oLink;        
        
        if (!isset($oLink)){
            $this->log('class.pmzhawsso.php: Could not connect to AD');
            return array(); 
        }
        // Add * if we are not searching for an exacte match (user samaccountname)
        if (!$exacte){
            if (substr($sKeyword , -1) != '*') {
                if ($sKeyword != '') {
                    $sKeyword = '*' . $sKeyword . '*';
                }
                else {
                    $sKeyword .= '*';
                }
            }
        }
		
        if ( isset( $aAuthSource['AUTH_SOURCE_DATA']['LDAP_TYPE']) && $aAuthSource['AUTH_SOURCE_DATA']['LDAP_TYPE'] == 'ad' && isset($aAuthSource['AUTH_SOURCE_DATA']['AUTH_SOURCE_USERS_FILTER']) ) {
            $sFilter = "(&(objectClass=*)(|(samaccountname=$sKeyword)(userprincipalname=$sKeyword))(objectCategory=person)".$aAuthSource['AUTH_SOURCE_DATA']['AUTH_SOURCE_USERS_FILTER'].')';
        } 
        else {
            $sFilter = "(&(objectClass=*)(|(samaccountname=$sKeyword)(userprincipalname=$sKeyword))(objectCategory=person))";
        }
        $this->log('class.pmzhawsso.php: Using this LDAP filter: ' . $sFilter);
        $aUsers  = array();
        
        try {
            $oSearch = @ldap_search($oLink, $aAuthSource['AUTH_SOURCE_BASE_DN'], $sFilter, array('dn','uid','samaccountname', 'cn','givenname','sn','mail','userprincipalname','objectcategory', 'manager'));
			
            if ($oError = @ldap_errno($oLink)) {
				$this->log('Search error: '.@ldap_err2str($oError));
                return $aUsers;
            }
            else {
                if ($oSearch) {
                    if (@ldap_count_entries($oLink, $oSearch) > 0) {
                        $sUsername = '';
                        $oEntry    = @ldap_first_entry($oLink, $oSearch);
                        do {
                            $aAttr = $this->getLdapAttributes ( $oLink, $oEntry );
							$sUsername = isset($aAttr['samaccountname']) ? $aAttr['samaccountname'] : '';
                            if ($sUsername != '') {
                                $aUsers[] = array('sUsername' => $sUsername,
                                                'sFullname' => $aAttr['cn'],
                                                'sFirstname' => isset($aAttr['givenname']) ? $aAttr['givenname'] : '',
                                                'sLastname' => isset($aAttr['sn']) ? $aAttr['sn'] : '',
                                                'sEmail' => isset($aAttr['mail']) ? $aAttr['mail'] : ( isset($aAttr['userprincipalname'])?$aAttr['userprincipalname'] : '') ,
                                                'sDN' => $aAttr['dn'] ,
                                                'sManagerDN' => isset($object['manager']) ? is_array($object['manager']) ? $object['manager'][0] : $object['manager'] : ''); 
                            }
                        } while ($oEntry = @ldap_next_entry($oLink, $oEntry));
                    }
                }
            }
        }
        catch (Exception $error) {
            $this->log('class.pmzhawsso.php: Error in searchUsers: ' . $error->getMessage());
            return array();
        }
        
        return $aUsers;
    }
    
    /**
     * Register automatically the user in ProcessMaker
     *
     * @param String $authSource to use
     * @param String $strUser name (SAMAccountName)
     * @param String $strPass (we don't really need in SSO)
     * @return Integer If the user was created correctly
     */
    public function automaticRegister($authSource, $strUser, $strPass) {
        try {
            $RBAC = RBAC::getSingleton();
            if (is_null($RBAC->userObj)) {
                $RBAC->userObj = new RbacUsers();
            }
            if (is_null($RBAC->rolesObj)) {
                $RBAC->rolesObj = new Roles();
            }
            $user = $this->searchUserByUid($strUser);
            $result  = 0;
            if (is_array($user)) {
                if ( $RBAC->singleSignOn ) {
                    $result = 1;
                }
                else {
                    if ($this->VerifyLogin($strUser, $strPass) === true) {
                        $result = 1;
                    }
                }
            }
            if ($result == 1) {
                $data = array();
                $data['USR_USERNAME']     = $user['sUsername'];
                $data['USR_PASSWORD']     = md5($user['sUsername']);
                $data['USR_FIRSTNAME']    = $user['sFirstname'];
                $data['USR_LASTNAME']     = $user['sLastname'];
                $data['USR_EMAIL']        = $user['sEmail'];
                $data['USR_DUE_DATE']     = date('Y-m-d', mktime(0, 0, 0, date('m'), date('d'), date('Y') + 2));
                $data['USR_CREATE_DATE']  = date('Y-m-d H:i:s');
                $data['USR_UPDATE_DATE']  = date('Y-m-d H:i:s');
                $data['USR_BIRTHDAY']     = date('Y-m-d');
                $data['USR_STATUS']       = 1;
                $data['USR_AUTH_TYPE']    = strtolower($authSource['AUTH_SOURCE_PROVIDER']);
                $data['UID_AUTH_SOURCE']  = $authSource['AUTH_SOURCE_UID'];
                $data['USR_AUTH_USER_DN'] = $user['sDN'];
                $userUID                  = $RBAC->createUser($data, 'PROCESSMAKER_OPERATOR');
                $data['USR_STATUS']       = 'ACTIVE';
                $data['USR_UID']          = $userUID;
                $data['USR_PASSWORD']     = md5($userUID);
                $data['USR_ROLE']         = 'PROCESSMAKER_OPERATOR';
                require_once 'classes/model/Users.php';
                $userInstance = new Users();
                $userInstance->create($data);
                $this->log('Automatic Register for user "' . $user['sUsername'] . '".');
				
				// If defined default group, add user to this group
				$edata = unserialize($authSource['AUTH_SOURCE_DATA']);
				$groupName = $edata['AUTH_SOURCE_AUTO_REGISTER_DEFAULT_GRP'];
				
				// Find group uid based on the enterd group name
				if (!empty($groupName)){
					require_once 'classes/model/Content.php';
					require_once 'classes/model/Groupwf.php';
					$crit = new Criteria('workflow');
					$crit->clearSelectColumns();
					$crit->addSelectColumn( ContentPeer::CON_ID );
					$crit->add(ContentPeer::CON_CATEGORY,  'GRP_TITLE');
					$crit->add(ContentPeer::CON_VALUE,  $groupName);
					$crit->add(ContentPeer::CON_LANG,  SYS_LANG );					
					
					$oDataset = GroupwfPeer::doSelectRS($crit);
					$oDataset->setFetchmode(ResultSet::FETCHMODE_ASSOC);
					$oDataset->next();
					$aRow = $oDataset->getRow();				
					if ($aRow) {
						G::LoadClass("groups");					
						$groupUID = $aRow['CON_ID'];
						$grpInstance = new Groups();
						$grpInstance->addUserToGroup($groupUID, $userUID);
						$this->log('User "' . $user['sUsername'] . '" added to group "' . $groupName . '".');
					}
				}
            }
            return $result;
        }
        catch (Exception $error) {
            throw $error;
        }
    }
}