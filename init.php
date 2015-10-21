<?php
/**
 * auth_tlsclient plugin for Tiny Tiny RSS
 * Allows for more flexible authentication via SSL/TLS Client certificates
 * @author maff (maff@maff.scot)
 * @copyright BSD3
 * @version 0.01
 */

/**
 * Inspired by the SSL client certificate support in auth_remote
 * Requires the following variables be set by the server (with or without REDIRECT_ prefix): {{{
 * SSL_CLIENT_VERIFY
 * SSL_CLIENT_M_SERIAL
 * SSL_CLIENT_S_DN
 * SSL_CLIENT_CERT
 *
 * This plugin does not make full use of SSL_CLIENT_* variables set by apache2 mod_ssl
 * due to a lack of compatibility with what is available by default in nginx.
 * }}}
 */

class Auth_TlsClient extends Plugin implements IAuthModule {
	//Private variables, functions {{{
	private $host; private $base;
	private function _log($msg, $level=E_USER_WARNING) {
		trigger_error($msg,$level);
	}
	private function _resolveUser($fingerprint) {
		$fingerprint = db_escape_string($fingerprint);
		if(!$fingerprint) return '';
		$result = db_query("SELECT owner_uid, content FROM ttrss_plugin_storage
			WHERE name = 'auth_tlsclient'");
		if (db_num_rows($result) < 1) return '';
		$uids=array();
		for ($i=0;$i<db_num_rows($result);$i++) {
			$res=unserialize(db_fetch_result($result,$i,'content'));
			if (!is_array($res)) continue;
			if ($res['auth_tlsclient_certfp'] === $fingerprint) $uids[] = db_fetch_result($result,$i,'owner_uid');
		}
		if (count($uids) === 0) return '';
		if (count($uids) > 1) {
			trigger_error("Multiple uids found for certfp $fingerprint, bailing.", E_USER_WARNING);
			return '';
		}
		$result = db_query("SELECT login FROM ttrss_users WHERE id = '".$uids[0]."'");
		if (db_num_rows($result) === 1) return db_escape_string(db_fetch_result($result,0,'login'));
		return '';
	}
	private function _getCertFP() {
		//Actually support REDIRECT_SSL_CLIENT_* like I said in the header from the beginning, oops
		$ssl_verify = $_SERVER["SSL_CLIENT_VERIFY"];
		if (!$ssl_verify) $ssl_verify = $_SERVER["REDIRECT_SSL_CLIENT_VERIFY"];
		$ssl_cert = $_SERVER["SSL_CLIENT_CERT"];
		if (!$ssl_cert) $ssl_cert = $_SERVER["REDIRECT_SSL_CLIENT_CERT"];
		//We expect that the underlying webserver will have validated against a known CA
		if ($ssl_verify !== "SUCCESS") return false;
		//We also expect that the server passes the client certificate in PEM format
		if (!strlen($ssl_cert)) return false;
		//Get the fingerprint of the certificate
		//Try SHA256 first
		$fp = openssl_x509_fingerprint($ssl_cert, 'sha256', false);
		if ($fp) return $fp;
		//Else fall back to SHA1
		return openssl_x509_fingerprint($ssl_cert, 'sha1', false);
		//Not implementing an MD5 fallback because if you're still using MD5 certificates you clearly don't care about being secure
	}
	//}}}

	//Base module scaffolding {{{
	function api_version() { return 2; }

	function about() {
		return array(
			0.01, #Version
			"Authenticates users using SSL/TLS client certificates", #Description
			"maff", #Author
			true); #is system plugin
	}

	function init($host) {
		$this->host = $host;
		$this->base = new Auth_Base();
		$host->add_hook($host::HOOK_AUTH_USER, $this);
		$host->add_hook($host::HOOK_PREFS_TAB, $this);
	}
	//}}}

	//Authentication {{{
	function authenticate($login,$password) {
		$fp = $this->_getCertFP();
		$uname = $this->_resolveUser($fp);
		if (!$uname) {
			$this->_log("Failed to resolve client certificate with fingerprint $fp to a uid.");
			return false;
		}
		$uid = $this->base->auto_create_user($uname, $password);
		if(!$uid) return false;
		$_SESSION["fake_login"] = $uname; $_SESSION["fake_password"] = '123789abcxyz';
		$_SESSION["hide_hello"] = true; $_SESSION["hide_logout"] = true;
		return $uid;
	}
	//}}}

	//PrefsTab/Configuration {{{
	function hook_prefs_tab($args) {
		if ($args!="prefPrefs") return;
		print "<div dojoType='dijit.layout.AccordionPane' title='".__('TLS Client Certificate Authentication')."'>";
		print "<p>".__('If you have registered your certificate already, its fingerprint will appear in the box below. If you have not, use the Register button to view and confirm your certificate fingerprint.')."</p>";
		print "<form dojoType='dijit.form.Form'>";
		print "<script type='dojo/method' event='onSubmit' args='evt'>
			evt.preventDefault();
			if (this.validate()) {
				new Ajax.Request('backend.php', {
					parameters: dojo.objectToQuery(this.getValues()),
					onComplete: function(transport) {
						notify_info(transport.responseText);
					}
				});
			}
			</script>";
		print "<input dojoType='dijit.form.TextBox' style='display:none' name='op' value='pluginhandler' />";
		print "<input dojoType='dijit.form.TextBox' style='display:none' name='method' value='save' />";
		print "<input dojoType='dijit.form.TextBox' style='display:none' name='plugin' value='auth_tlsclient' />";
		print "<label for='certfp_cur'>".__("Currently-stored client certificate")."</label>";
		print "<input dojoType='dijit.form.TextBox' name='certfp_cur' value='".$this->host->get($this, "auth_tlsclient_certfp")."' readonly /><br />";
		print "<label for='certfp'>".__("Client certificate to be stored")."</label>";
		print "<input dojoType='dijit.form.TextBox' id='certfp' name='certfp' value='' readonly /><br />";
		print "<button dojoType='dijit.form.Button' type='button' onclick='dijit.byId(\"certfp\").attr(\"value\",\"".$this->_getCertFP()."\");'>".__('Insert certificate')."</button>";
		print "<button dojoType='dijit.form.Button' type='button' onclick='dijit.byId(\"certfp\").attr(\"value\",\"\");'>".__('Clear certificate')."</button><br />";
		print "<button dojoType='dijit.form.Button' type='submit'>".__('Save')."</button>";
		print "</form></div>";
	}

	function save() {
		if (!isset($_POST["certfp"]) || !isset($_SESSION["uid"])) return;
		$this->host->set($this, "auth_tlsclient_certfp", db_escape_string($_POST['certfp']));
		echo __('Client certificate updated.');
	}
	//}}}
}

?>
