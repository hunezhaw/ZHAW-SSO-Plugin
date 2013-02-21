<?php
/**
 * The Windows SSO plugin brings ability to use SSO with Active Directory users
 *
 * @author Julio Cesar Laura <juliocesar at colosa dot com> <contact at julio-laura dot com>
 * @package plugins.windowsSSO
 * @copyright Copyright (C) 2004 - 2011 Colosa Inc.
 */

// Load dependences
G::LoadClass('plugin');

class pmzhawssoPlugin extends PMPlugin {

    /**
     * This method initializes the plugin attributes
     *
     * @param String $namespace The namespace of the plugin
     * @param String $filename The filename of the plugin
     * @return String $result
     */
     function pmzhawssoPlugin($namespace, $filename = null) {
	 	G::log('pmzhawsso: read config');	
        $version = self::getPluginVersion($namespace);
        // Setting the attributes
        $result = parent::PMPlugin($namespace, $filename);
        $config = parse_ini_file(PATH_PLUGINS . 'pmzhawsso' . PATH_SEP . 'pluginConfig.ini');
        $this->sFriendlyName = $config['name'];
        $this->sDescription  = $config['description'];
        $this->sPluginFolder = $config['pluginFolder'];
        $this->sSetupPage    = $config['setupPage'];
        $this->iVersion      = $version;
        $this->aWorkspaces   = null;
        $this->aDependences  = null;
        $this->bPrivate      = false;
        return $result;
    }

    /**
     * The setup function that handles the registration of the menu also
     * checks the current version of PM and register the menu according to that
     *
     * @return void
     */
    public function setup() {
        if (!defined('PM_SINGLE_SIGN_ON')) {
            define('PM_SINGLE_SIGN_ON', 'PM_SINGLE_SIGN_ON');
        }
        $this->registerTrigger(PM_SINGLE_SIGN_ON, 'singleSignOn');
        $this->copyFiles();
    }

    /**
     * The default install method that is called whenever the plugin is installed in ProcessMaker
     * internally calls the method copyInstallFiles since is the only action that is executed
     * @return void
     */
    public function install() {
    }

    /**
     * The default enable method that is called whenever the plugin is enabled in ProcessMaker
     * internally calls the method copyInstallFiles since is the only action that is executed
     *
     * @return void
     */
    public function enable() {
        $this->copyFiles();
		
		// We need to know if plugin is enabled, when the system is not fully initialised
		$fpt = fopen(PATH_PLUGINS . 'pmzhawsso/enabled.txt', 'a');
        fwrite($fpt, "enabled");
        fclose($fpt);
    }

    /**
     * The default disable method that is called whenever the plugin is disabled in ProcessMaker
     * internally deletes the copied files so these don't trigger errors about dependencies with these
     *
     * @return void
     */
    public function disable() {
        $rbacFile = PATH_RBAC . 'plugins' . PATH_SEP . 'class.pmzhawsso.php';
        $this->delete($rbacFile, true);
		$this->delete(PATH_PLUGINS . 'pmzhawsso/enabled.txt');
    }

    /**
     * Add a line in the log
     *
     * @author Philipp Hungerbühler
     * @param String $text The text to save in the log
     * @return void
     */
    private function log($text) {
        if (!class_exists('pmzhawssoClass')) {
            require_once PATH_PLUGINS . 'pmzhawsso/class.pmzhawsso.php';
        }
        pmzhawssoClass::log($text);
    } 

    /**
     * This method get the version of this plugin, when the plugin is packaged in the tar.gz
     * the file "version" in the plugin folder has this information for development purposes,
     * we calculate the version using git commands, because the repository is in GIT
     *
     * @param String $namespace The namespace of the plugin
     * @return String
     */
    private static function getPluginVersion($namespace) {
        $pathPluginTrunk = PATH_PLUGINS . PATH_SEP . $namespace;
        if (file_exists($pathPluginTrunk . PATH_SEP . 'VERSION')) {
            $version = trim(file_get_contents($pathPluginTrunk . PATH_SEP . 'VERSION'));
        }
        else {
            $version = 'Initial Version';  
        }
        return $version;
    }

    /**
     * Copy the files in data folder to the specific folders in ProcessMaker core
     *
     * @return void
     */
    private function copyFiles() {
        $rbacFile = PATH_RBAC . 'plugins' . PATH_SEP .'class.pmzhawsso.php';
        $this->copy('data' . PATH_SEP . 'class.pmzhawsso.php', $rbacFile, false, true);
    }
}

// Register this plugin in the Plugins Singleton
$oPluginRegistry =& PMPluginRegistry::getSingleton();
$oPluginRegistry->registerPlugin('pmzhawsso', __FILE__);