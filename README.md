ZHAW-SSO-Plugin
===============

Single Sign On Plugin for ProcessMaker (Version 2.0.44)

This is a single-sign-on plugin for the popular PorcessMaker open source, workflow management software suite. By default ProcessMaker does not provide a SSO plugin for Windows/IIS environments.The ZHAW-SSO plugin takes advantage of the Windows Integrated authentication, which can be enabled in IIS. Once enabled (see installation) each request reaching PM will be authenticated be IIS. The corresponding user name can be accessed be checking the $_SERVER[“REMOTE_USER”] server variable. The open source version by default does not provide a hook for bypassing the sysLogin screen, which is called and rendered even before the system is fully initialized. At the point when the login is shown the different plugins are still not loaded and cannot be accessed. This proved to be a challenge. The resulting solution was to implement a small hack for the base PM framework. This hack consists of three files of the base PM framework, which were slightly extended to add a SSO hook. 

Attention: As a result of these small changes to the base framework the plugin depends on the used version of PM. The plugin was only tested on PM 2.0.44. For previous or future versions of PM the changed files may need to be adapted.

Functionality
-------------
AS of writing this document the ZHAW-SSO plugin provides the following functionality:

•	Normal LDAP authentication: If the IIS Windows Integrated authentication is not activated (the server variable is not set), the plugin provides the same functionality as the normal LDAP plugin (authenticating users by performing an LDAP bind).
•	SSO login, bypassing sysLogin: When IIS Windows Integrated authentication is activated; IIS will set the REMOTE_USER variable to the users name. This user name is then taken for initializing PM, assuming, that this user is authenticated. PM does not have a password for this user; therefore a LDAP bind authentication is not possible. Once authenticated through the SSO plugin, the user is forwarded to his last location in PM.
•	Auto-registration: If the user is not registered in PM, but is returned by the configured LDAP filter, a new user account is generated the first time the user logs in. 
•	Revert to normal sysLogin: In order for accessing the normal sysLogin (for example to login as Admin), a user can use the normal logout functionality. This will forward to the sysLogin and allow a normal login. A reload of the page will again perform a SSO login.
•	Web services: The PM web services were not tested with SSO (open task). For the moment it is recommended to us a PM account when accessing the web services.

Please see the documentation under pmzhawsso\documentation\121214_PM_IIS_SSO.pdf

Philipp Hungerbühler