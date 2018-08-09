<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

defined('INTERNAL') || die();
require_once(get_config('docroot').'auth/lib.php');
require_once(__DIR__.'/autoload.php');

/**
 * Authenticates users with OpenID Connect.
 */
class AuthOidc extends Auth {

    public $client = null;

    /**
     * Constructor.
     *
     * @param int $id Auth instance ID.
     * @return bool Success/Failure.
     */
    public function __construct($id = null) {
        $this->type = 'oidc';
        $this->has_instance_config = true;
        $this->instanceid = $id;
        if (!empty($id)) {
            return $this->init($id);
        }
        return true;
    }

    /**
     * Returns whether the authentication instance can automatically create a user record.
     *
     * @return bool Whether users can be autocreated.
     */
    public function can_auto_create_users() {
        $currentconfig = PluginAuthOidc::get_current_config();
        return (!empty($currentconfig['autocreateusers'])) ? true : false;
    }

    /**
     * Initialize plugin.
     *
     * @param int $id Auth instance id.
     * @return bool Whether plugin has been initialized.
     */
    public function init($id = null) {
        $this->ready = parent::init($id);
        return $this->ready;
    }

    /**
     * Process an authorization request.
     *
     * Operations:
     *     - Auto creates users.
     *     - Sets up user object for linked accounts.
     *
     * @param string $oidcuniqid The OIDC unique identifier received.
     * @param array $tokenparams Received token parameters.
     * @param \auth_oidc\jwt $idtoken Received id token.
     * @return bool Success/Failure.
     */
    public function request_user_authorise($oidcuniqid, $tokenparams, $idtoken) {
        global $USER, $SESSION;
        $this->must_be_ready();

        $email = $idtoken->claim('PreferredEmail');
        if(!$email) {
            $email = $idtoken->claim('email');
        }
        if ($email) {
	        $email = strtolower($email);
        }

        $firstname = $idtoken->claim('FirstName');
        if (!$firstname) {
	        $firstname = $idtoken->claim('name');
        }

        $lastname = $idtoken->claim('LastName');
	    if (!$lastname && $firstname
		    && count($nameparts = explode(" ", $firstname)) > 1) {
		    $lastname = trim(array_pop($nameparts));
		    $firstname = trim(implode(" ", $nameparts));
	    }

	    $upn = $email;
	    $student_number = $idtoken->claim('student_number');
		if ($student_number) {
			// Get the UPN for OP its student id with 's' at end.
			$upn = $this->client->get_upn($idtoken);
		}
        if ($upn && !empty($upn)) {
            $username = $upn;
        }
        else {
            // Username was not present in claims.
            throw new \AuthInstanceException(get_string('errorauthnousername', 'auth.oidc'));
        }
        $create = false;
        try {
            $user = new \User;
            try {
                $user->find_by_instanceid_username($this->instanceid, $username, true);
            }
            catch (\AuthUnknownUserException $e) {
            	try {
		            // User not present in this auth instance, so pick the user from other auth instance and update
		            $user->find_by_username($username);
		            $user->authinstance = $this->instanceid;
	            }
	            catch (\AuthUnknownUserException $e) {
            		if ($student_number) {
			            throw new AuthUnknownUserException("User with username \"$username\" is not known");
		            }
		            $oldusername = $this->find_username_by_email($email);
            		if($oldusername) {
			            $user->find_by_username($oldusername);
			            $user->authinstance = $this->instanceid;
			            $user->username = get_new_username($username, 200);
		            }
		            else {
			            throw new AuthUnknownUserException("User with username \"$username\" is not known");
		            }
	            }
            }

            if ($user->get('suspendedcusr')) {
                die_info(get_string('accountsuspended', 'mahara', strftime(get_string('strftimedaydate'), $user->get('suspendedctime')), $user->get('suspendedreason')));
            }

            // Update the user with latest detials
            foreach (array(
                "firstname" => $firstname,
                "lastname" => $lastname,
                "email" => $email
                     ) as $field => $value) {
                if ($value && !empty($value) && $user->$field != $value) {
                    $user->$field = $value;
                    set_profile_field($user->id, $field, $user->$field);
                }
            }
        }
        catch (\AuthUnknownUserException $e) {
            if ($this->can_auto_create_users() === true) {
                $institution = new \Institution($this->institution);
                if ($institution->isFull()) {
                    throw new \XmlrpcClientException('OpenID Connect login attempt failed because the institution is full.');
                }
                $user = new \User;
                $create = true;
            }
            else {
                return false;
            }
        }

        if ($create === true) {
            $user->passwordchange = 0;
            $user->active = 1;
            $user->deleted = 0;
            $user->expiry = null;
            $user->expirymailsent = 0;
            $user->lastlogin = time();
            $user->firstname = $firstname;
            $user->lastname = $lastname;
            $user->email = $email;
            if ($student_number && !empty($student_number)) {
                $user->studentid = $student_number;
            }
            $user->authinstance = $this->instanceid;

            db_begin();
            $user->username = get_new_username($username, 200);
            $user->id = create_user($user, array(), $this->institution, $this, $username);
            $userobj = $user->to_stdclass();

            db_commit();

            $user = new User;
            $user->find_by_id($userobj->id);
        }
        self::import_user_settings($user, $idtoken);
        $user->commit();
        $USER->reanimate($user->id, $this->instanceid);
        $SESSION->set('authinstance', $this->instanceid);
        return true;
    }

    private function find_username_by_email($email) {
    	if ($email) {
		    $email = strtolower($email);

		    $sql = 'SELECT
                    username
                FROM
                    {usr}
                WHERE
                    LOWER(email) = ?
                    AND username LIKE \'%t\'';

		    $olduser = get_record_sql($sql, array($email));
		    if ($olduser) {
			    return $olduser->username;
		    }
	    }

	    throw new AuthUnknownUserException("User with email \"$email\" is not known");

	    return null;
    }

    /**
     * Update the student city and country
     *
     * * City
     * * Country
     *
     * @param User $user
     * @param stdClass $idtoken
     */
    private function import_user_settings($user, $idtoken) {
        $imported = array();

        // Student Id
        $studentid = $idtoken->claim('student_number');
        if ($studentid && !empty($studentid)) {
            if (get_profile_field($user->id, 'studentid') != $studentid) {
                set_profile_field($user->id, 'studentid', $studentid);
            }
            $imported[] = 'studentid';
        }
		if ($studentid) {
			// City
			$city = $idtoken->claim('City');
			if ($city && !empty($city)) {
				if (get_profile_field($user->id, 'town') != $city) {
					set_profile_field($user->id, 'town', $city);
				}
				$imported[] = 'town';
			}

			// Country
			$newcountry = strtolower($idtoken->claim('Country'));
			if ($newcountry && !empty($newcountry)) {
				$newcountry = strtolower($newcountry);
				$validcountries = array_keys(getoptions_country());
				if (in_array($newcountry, $validcountries)) {
					set_profile_field($user->id, 'country', $idtoken->claim('Country'));
				}
				$imported[] = 'country';
			}
		}
        return $imported;
    }

    /**
     * Overrides the default logout mechanism to do singout from Azure AD
     */
    public function logout() {
        global $CFG, $USER, $SESSION;

        $access_token = $SESSION->get('authaccesstoken');
        $auth = new \auth_oidc\loginflow\authcode();

        // logout of mahara
        $USER->logout();

        // tidy up the session for retries
        $SESSION->set('authaccesstoken', null);

        // redirect for logout with Azure AD
        $auth->sign_out($access_token);
    }


}

/**
 * Plugin configuration class
 */
class PluginAuthOidc extends PluginAuth {
    /**
     * Determine whether plugin is usable.
     *
     * @return bool Usable (true) or not usable (false).
     */
    public static function is_usable() {
        return true;
    }

    /**
     * Determine whether the plugin has global configuration.
     *
     * @return bool True if it does, false if it doesn't.
     */
    public static function has_config() {
        return true;
    }

    /**
     * Get currently configured global config options.
     *
     * @return array Array of current config values in the form [key] => [value].
     */
    public static function get_current_config() {
        $configparams = array(
            'clientid' => '',
            'clientsecret' => '',
            'authendpoint' => get_string('settings_authendpoint_default', 'auth.oidc'),
            'tokenendpoint' => get_string('settings_tokenendpoint_default', 'auth.oidc'),
            'logoutendpoint' => get_string('settings_logoutendpoint_default', 'auth.oidc'),
            'resource' => get_string('settings_resource_default', 'auth.oidc'),
            'autocreateusers' => 0,
            'studentdataurl' => '',
            'upnkey' => get_string('settings_upnkey_default', 'auth.oidc'),
        );
        $curconfig = array();
        foreach ($configparams as $key => $default) {
            $saved = get_config_plugin('auth', 'oidc', $key);
            $curconfig[$key] = ($saved !== null) ? $saved : $default;
        }
        return $curconfig;
    }

    /**
     * Get list of config options for the config form.
     *
     * @return array Array of config options and parameters to generate the config form.
     */
    public static function get_config_options() {
        $curconfig = static::get_current_config();
        return array(
            'class' => 'panel panel-body',
            'elements' => array(
                'clientid' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_clientid', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['clientid'],
                ),
                'clientsecret' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_clientsecret', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['clientsecret'],
                ),
                'authendpoint' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_authendpoint', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['authendpoint'],
                ),
                'tokenendpoint' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_tokenendpoint', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['tokenendpoint'],
                ),
                'logoutendpoint' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_logoutendpoint', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['logoutendpoint'],
                ),
                'resource' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_resource', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['resource'],
                ),
                'autocreateusers' => array(
                    'type' => 'switchbox',
                    'title' => get_string('settings_autocreateusers', 'auth.oidc'),
                    'defaultvalue' => $curconfig['autocreateusers'],
                    'help' => true,
                ),
                'studentdataurl' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_studentdataurl', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => false,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['studentdataurl'],
                ),
                'upnkey' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_upnkey', 'auth.oidc'),
                    'size' => 50,
                    'rules' => array(
                        'required' => true,
                    ),
                    'help'  => false,
                    'defaultvalue' => $curconfig['upnkey'],
                ),
            ),
            'renderer' => 'div',
        );
    }

    /**
     * Save received config options.
     *
     * @param \Pieform $form Form instance.
     * @param array $values Submitted values.
     */
    public static function save_config_options(Pieform $form, $values) {
        $curconfig = static::get_current_config();
        foreach ($curconfig as $key => $setvalue) {
            if (isset($values[$key])) {
                set_config_plugin('auth', 'oidc', $key, $values[$key]);
            }
        }
    }

    /**
     * Determine whether plugin has instance-specific configuration.
     *
     * @return bool True if it does, false if it doesn't.
     */
    public static function has_instance_config() {
        return true;
    }

    /**
     * Get currently configured instance values for a given instance id.
     *
     * @param int $instanceid Auth instance id.
     * @return array Array of configured instance values in the form [key] => [value].
     */
    public static function get_current_instance_config($instanceid) {
        $configparams = array(
            'institutionattribute' => '',
            'institutionvalue' => '',
        );
        $curconfig = array();
        foreach ($configparams as $key => $default) {
            if (!empty($instanceid)) {
                $saved = get_config_plugin_instance('auth', $instanceid, $key);
                $curconfig[$key] = ($saved !== null) ? $saved : $default;
            }
            else {
                $curconfig[$key] = $default;
            }
        }
        return $curconfig;
    }

    /**
     * Get instance config form parameters.
     *
     * @param string $institution The institution name.
     * @param int $instance The auth instance id.
     * @return array Array of instance config form options.
     */
    public static function get_instance_config_options($institution, $instance = 0) {
        $curconfig = static::get_current_instance_config($instance);
        return array(
            'class' => 'panel panel-body',
            'elements' => array(
                'instance' => array(
                    'type'  => 'hidden',
                    'value' => $instance,
                ),
                'instancename' => array(
                    'type'  => 'hidden',
                    'value' => 'OIDC',
                ),
                'institution' => array(
                    'type'  => 'hidden',
                    'value' => $institution,
                ),
                'authname' => array(
                    'type'  => 'hidden',
                    'value' => 'oidc',
                ),
                'institutionattribute' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_institutionattribute', 'auth.oidc', $institution),
                    'rules' => array(
                        'required' => false,
                    ),
                    'defaultvalue' => $curconfig['institutionattribute'],
                    'help' => true,
                ),
                'institutionvalue' => array(
                    'type'  => 'text',
                    'title' => get_string('settings_institutionvalue', 'auth.oidc'),
                    'rules' => array(
                        'required' => false,
                    ),
                    'defaultvalue' => $curconfig['institutionvalue'],
                    'help' => true,
                ),
            ),
            'renderer' => 'div',
        );
    }

    /**
     * Save instance config options.
     *
     * @param \Pieform $form Form instance.
     * @param array $values Submitted values.
     * @return array Submitted values.
     */
    public static function save_instance_config_options($values, Pieform $form) {
        $authinstance = new \stdClass;
        $authinstance->instancename = $values['instancename'];
        $authinstance->institution = $values['institution'];
        $authinstance->authname = $values['authname'];

        if (!empty($values['instance'])) {
            $current = get_records_assoc('auth_instance_config', 'instance', $values['instance'], '', 'field, value');
            $authinstance->id = $values['instance'];
            update_record('auth_instance', $authinstance, array('id' => $values['instance']));
        }
        else {
            $lastinstance = get_records_array('auth_instance', 'institution', $values['institution'], 'priority DESC', '*', '0', '1');
            $authinstance->priority = (!empty($lastinstance)) ? $lastinstance[0]->priority + 1 : 0;
            $values['instance'] = insert_record('auth_instance', $authinstance, 'id', true);
        }

        $curconfig = static::get_current_instance_config($values['instance']);
        foreach ($values as $key => $value) {
            if (isset($curconfig[$key])) {
                set_config_plugin_instance('auth', 'oidc', $values['instance'], $key, $value);
            }
        }

        return $values;
    }

    /**
     * Add elements to the login form.
     *
     * This adds the "OpenID Connect" button to the login form and hides the existing login form.
     *
     * @return array Array of new elements.
     */
    public static function login_form_elements() {
        $hideloginform = '<style>#login_login_container{display: none;} #login_login_extra_container strong {display: none;}</style>';
        if (isset($_REQUEST["showlogin"]) && $_REQUEST["showlogin"]) {
            $hideloginform = '';
        }
        return array(
            'loginoidc' => array(
                'value' => $hideloginform
                    .'<div class="login-externallink">'
                            .'<p>'.get_string('login_description', 'auth.oidc').'</p>'
                            .'<a class="btn btn-primary btn-xs" href="'.get_config('wwwroot').'auth/oidc/redirect.php">'
                            .get_string('login', 'auth.oidc').'</a></div>'
            ),
        );
    }

    /**
     * Can be overridden by plugins that inject the things they need
     * in the login form and don't need the standard elements.
     */
    public static function need_basic_login_form() {
        return false;
    }

}
