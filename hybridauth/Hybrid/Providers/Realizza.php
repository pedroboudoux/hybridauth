<?php

class Hybrid_Providers_Realizza extends Hybrid_Provider_Model_OAuth2 {
 
	public $scope = "dados-perfil";

	/**
	 * {@inheritdoc}
	 */
	function initialize() {
		parent::initialize();

		// Provider api end-points
		$this->api->authorize_url = Configure::read('Hybridauth')['Realizza']['uri'];
		$this->api->token_url = Configure::read('Hybridauth')['Realizza']['uri_token'];
		$this->api->token_info_url = Configure::read('Hybridauth')['Realizza']['uri_token'];

		// Google POST methods require an access_token in the header
		$this->api->curl_header = array("Authorization: OAuth " . $this->api->access_token);

		// Override the redirect uri when it's set in the config parameters. This way we prevent
		// redirect uri mismatches when authenticating with Google.
		if (isset($this->config['redirect_uri']) && !empty($this->config['redirect_uri'])) {
			$this->api->redirect_uri = $this->config['redirect_uri'];
		}
	}
    
    function getUserProfile() {
        // refresh tokens if needed
        $this->refreshToken();
        
        $response = $this->api->api(Configure::read('Hybridauth')['Realizza']['uri_profile']);
        if (!isset($response->id) || isset($response->error)) {
            throw new Exception("User profile request failed! {$this->providerId} returned an invalid response:" . Hybrid_Logger::dumpData( $response ), 6);
        }
        
        $this->user->profile->identifier = (property_exists($response, 'id')) ? $response->id : ((property_exists($response, 'id')) ? $response->id : "");
        $this->user->profile->displayName = (property_exists($response, 'name')) ? $response->name : "";
        $this->user->profile->email = (property_exists($response, 'username')) ? $response->username :  "";
        
        return $this->user->profile;
    }

	/**
	 * {@inheritdoc}
	 */
	function loginBegin() {
		$parameters = array("scope" => $this->scope, "access_type" => "offline");
		$optionals = array("scope", "access_type", "redirect_uri", "approval_prompt", "hd", "state");

		foreach ($optionals as $parameter) {
			if (isset($this->config[$parameter]) && !empty($this->config[$parameter])) {
				$parameters[$parameter] = $this->config[$parameter];
			}
			if (isset($this->config["scope"]) && !empty($this->config["scope"])) {
				$this->scope = $this->config["scope"];
			}
		}

		if (isset($this->config['force']) && $this->config['force'] === true) {
			$parameters['approval_prompt'] = 'force';
		}

		Hybrid_Auth::redirect($this->api->authorizeUrl($parameters));
	}

	/**
	 * Add query parameters to the $url
	 *
	 * @param string $url    URL
	 * @param array  $params Parameters to add
	 * @return string
	 */
	function addUrlParam($url, array $params) {
		$query = parse_url($url, PHP_URL_QUERY);

		// Returns the URL string with new parameters
		if ($query) {
			$url .= '&' . http_build_query($params);
		} else {
			$url .= '?' . http_build_query($params);
		}
		return $url;
	}

}
