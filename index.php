<?php
// Ross Grambo
// September  4th, 2015
// Purpose: The backend for the application: "College Party".

require_once(dirname(__FILE__) . '/config.php');
require_once __DIR__ . '/vendor/autoload.php';

error_reporting(E_ALL); ini_set('display_errors', '1');
date_default_timezone_set('UTC');

$CHECKLOGINFAILED = "Not Authorized to Perform Action";

// Default value if something goes wrong
$value = "An error has occurred";

// -----------------------------------------------------------------------------------------------------
// REQUEST ROUTING
// -----------------------------------------------------------------------------------------------------

// Handles all Post requests
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	// Read the json from the post request
	//$data = json_decode(trim(file_get_contents('php://input')), true);
	$data = json_decode($_POST["data"], true);
	$action = $data["action"];

	// POST request must declare an action
	if (isset($action)) {
		switch ($action)
		{	
			// Create a party
			case "createparty":
				if (checkLogin()) {
					$data = $data["party"];
					$value = post($data['name'], $data['description'], $data['restriction'], $data['time'], $data['address']);
				}
				break;

			// Create a user
			case "createuser":
				$data = $data["user"];
				if (!isset($data["FacebookToken"])) {
					$value = register($data["username"], $data["firstname"], $data["lastname"], 
						$data["password"], $data["email"], "");
				} else {
					$value = handleFacebookTokenRegistration($data["FacebookToken"]);
				}
				break;
		}
	}
// Handles all Delete requests
} else if ($_SERVER['REQUEST_METHOD'] == 'DELETE') {
	// TODO add delete for users
	// Determine if the user is logged in
	if (checkLogin()) {
		$data = json_decode(file_get_contents("php://input"), true);
		$value = delete($data['id']);
	}
// Handles all Get requests
} else if ($_SERVER['REQUEST_METHOD'] == 'GET') {
	// GET request must have decalred an action
	if (isset($_GET["action"]))
	{
		switch ($_GET["action"])
		{
			// Login with either a facebook token or username and password
			case "login":
				if ($_GET["FacebookToken"]) {
					$value = loginFacebook($_GET["FacebookToken"]);
				} else {
					$value = login($_GET["username"], $_GET["password"]);
				}
				break;
			// Handle a special request for testing purposes (For Testing Purposes)
			case "special":
				$value = query("DELETE FROM users;");
				break;
			// Checks the the cookie the user sends in order to see if it is valid. (For Testing Purposes)
			case "checkCookie":
				if (checkLogin())
				{
					$cookie = $_COOKIE['collegepartyauth'];
					$value = $cookie['user'];
				} else {
					$value = $CHECKLOGINFAILED;
				}
				break;
			// Standard call that returns party information
			case "get":
				if (checkLogin()) {
					if (isset($_GET["lat"]) && isset($_GET["lng"]) && isset($_GET["miles"]))
						$value = get($_GET["lat"], $_GET["lng"], $_GET["miles"]);
					else
						$value = "Missing argument";
					break;
				}
				break;
			// Returns a user
			case "getuser":
				if (isset($_GET["id"])) {
					$value = query("SELECT * FROM users WHERE id=".$_GET["id"]);
					$value = $value[0];
				}
				break;
			// Returns a user
			case "getuserfromusername":
				$value = getUser($_GET["username"]);
				break;
			// Returns all users (For Testing Purposes)
			case "getusers":
				$value = query("SELECT * FROM users");
				exit(var_dump($value));
			// Creates the tables in sql (For Testing Purposes)
			case "createtables":
				$value = createtables();
				break;
			// Logs out the user (Works on both facebook or non-facebook login)
			case "logout":
				$value = logout();
				break;
		}
	}
}

exit(json_encode($value));

// -----------------------------------------------------------------------------------------------------
// MAIN FUNCTIONS
// -----------------------------------------------------------------------------------------------------

// Connects to the database and returns that connection
function connect()
{
	try {
		$db = new PDO("mysql:host=example.someID.us-west-2.rds.amazonaws.com:3306;dbname=".DB_NAME, DB_USER, DB_PASS);
		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
	} catch (PDOException $ex) {
		exit($ex->getMessage());
	}

	return $db;
}

// Querys the database with the given sql code
function query($sql)
{
	$db = connect();

	try {
		// Prepare the statement
		$stmt = $db->prepare($sql);

		// Execute the statement
		$stmt->execute();

		// If it's a select, grab all of the data
		if (startsWith($sql, "SELECT")) {
			$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
		} elseif (startsWith($sql, "INSERT INTO")) {
			$result = $db->lastInsertId();
		} else {
			if ($stmt->errorCode() == "00000") {
				$result = true;
			} else {
				$result = false;
			}
		}
 	 } catch (PDOException $e) {
		header("HTTP/1.1 400 Bad Request");
    		die("Error: ".$e->getMessage());
	}

	if (!$result) {
	$result = array();
	}

	return $result;
}

// -----------------------------------------------------------------------------------------------------
// ACTION REQUESTS
// -----------------------------------------------------------------------------------------------------

// Creates the tables if they do not exist
function createtables() {
	$sql = "CREATE TABLE IF NOT EXISTS parties (
		id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
		name VARCHAR(30) NOT NULL,
		address VARCHAR(30) NOT NULL,
		time TIMESTAMP NOT NULL,
		lat DECIMAL(10, 8) NOT NULL,
		lng DECIMAL(11, 8) NOT NULL,
		datecreated TIMESTAMP DEFAULT '0000-00-00 00:00:00',
		dateupdated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		);";

	$sql = "CREATE TABLE IF NOT EXISTS users (
		id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
		username VARCHAR(30) NOT NULL UNIQUE,
		password VARCHAR(123) NOT NULL,
		firstname VARCHAR(30) NOT NULL,
		lastname VARCHAR(30) NOT NULL,
		email VARCHAR(100),
		facebookId VARCHAR(20),
		datecreated TIMESTAMP DEFAULT '0000-00-00 00:00:00',
		dateupdated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		);";

	return query($sql);
}

// Performs a get with the given latitude, longitude, and distance in miles.
function get($lat, $lng, $miles) {
	$convertedMiles = $miles / 69;
	$sql = "SELECT * FROM parties 
		WHERE (lat BETWEEN " . ($lat - $convertedMiles) . " AND " . ($lat + $convertedMiles) . ") AND (lng BETWEEN " . 
			($lng - $convertedMiles) . " AND ". ($lng + $convertedMiles) . ");";

	return query ($sql);
}

// Deletes a party with the given id
function delete($id) {
	$userid = getUserId(getCookieUsername());
	$sql = "DELETE from parties WHERE id=".$id." AND userid=".$userid.";";
	return query ($sql);
}

// Creates a party with the given attributes (TODO: Change to object as parameter)
function post($name, $description, $restriction, $time, $address) {
	$userid = getUserId(getCookieUsername());
	$results = geocode($address);
	if ($results) {
		$lat = $results[0];
		$lng = $results[1];
		$address = $results[2];
	} else {
		die ("Could not geolocate address");
	}

	$db = connect();

	$stmt = $db->prepare("INSERT INTO parties (name, description, restriction, time, lat, lng, address, datecreated, userid) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);");
	
	$result = $stmt->execute(array($name, $description, $restriction, $time, $lat, $lng, $address, date("Y-m-d H:i:s"), $userid));
    
	handleImage($db->lastInsertId());

	return $result;
}

// Returns a single user
function getUser($username) {
	$sql = "SELECT id, username, email, facebookId, datecreated FROM users WHERE username='".$username."';";

	$results = query($sql);

	if (!is_array($results) || count($results)==0) {
		return null;
	}

	$result = $results[0];

	return $result;
}

// -----------------------------------------------------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------------------------------------------------

function startsWith($haystack, $needle) {
	return $needle === "" || strrpos($haystack, $needle, -strlen($haystack)) !== FALSE;
}


// Stores the image in a local folder with the name set to the given id
function handleImage($id) {
	try {
		// Undefined | Multiple Files | $_FILES Corruption Attack
		// If this request falls under any of them, treat it invalid.
		if (
			!isset($_FILES['picture_0']['error']) ||
			is_array($_FILES['picture_0']['error'])
		) {
			throw new RuntimeException('Invalid parameters.');
		}

		// Check $_FILES['picture_0']['error'] value.
		switch ($_FILES['picture_0']['error']) {
			case UPLOAD_ERR_OK:
				break;
			case UPLOAD_ERR_NO_FILE:
				throw new RuntimeException('No file sent.');
			case UPLOAD_ERR_INI_SIZE:
			case UPLOAD_ERR_FORM_SIZE:
				throw new RuntimeException('Exceeded filesize limit.');
			default:
				throw new RuntimeException('Unknown errors.');
		}

		// DO NOT TRUST $_FILES['picture_0']['mime'] VALUE !!
		// Check MIME Type by yourself.
		$finfo = new finfo(FILEINFO_MIME_TYPE);
		if (false === $ext = array_search(
			$finfo->file($_FILES['picture_0']['tmp_name']),
			array(
				'jpg' => 'image/jpeg',
				'png' => 'image/png',
				'gif' => 'image/gif',
			),
			true
		)) {
			throw new RuntimeException('Invalid file format.');
		}

		  // You should also check filesize here. 
		if ($_FILES['picture_0']['size'] > 10000000) {
			throw new RuntimeException('Exceeded filesize limit.');
		}

		// You should name it uniquely.
		// DO NOT USE $_FILES['picture_0']['name'] WITHOUT ANY VALIDATION !!
		// On this example, obtain safe unique name from its binary data.
		if (!move_uploaded_file($_FILES['picture_0']['tmp_name'], "/var/www/html/images/".$id.".jpeg")) {
			throw new RuntimeException('Failed to move uploaded file.');
		}
        die("IMAGE UPLOADED");
	} catch (RuntimeException $e) {
		die ($e->getMessage());
	}
}

// Compresses an image file to prepare it for saving. (Want to crowd source this!)
function compress($source, $destination, $quality) {

	$info = getimagesize($source);

	if ($info['mime'] == 'image/jpeg') 
		$image = imagecreatefromjpeg($source);

	elseif ($info['mime'] == 'image/gif') 
		$image = imagecreatefromgif($source);

	elseif ($info['mime'] == 'image/png') 
		$image = imagecreatefrompng($source);

	imagejpeg($image, $destination, $quality);

	return $destination;
}

// Given an address, this function returns the best interpretation of it, 
// returning its latitude, longitude, and a new formatted address
function geocode($address){
 
	// url encode the address
	$address = urlencode($address);
	 
	// google map geocode api url
	$url = "http://maps.google.com/maps/api/geocode/json?address={$address}";
 
	// get the json response
	$resp_json = file_get_contents($url);
	 
	// decode the json
	$resp = json_decode($resp_json, true);
 
	// response status will be 'OK', if able to geocode given address 
	if($resp['status']=='OK') {
 
		// get the important data
		$lati = $resp['results'][0]['geometry']['location']['lat'];
		$longi = $resp['results'][0]['geometry']['location']['lng'];
		$formatted_address = $resp['results'][0]['formatted_address'];
		 
		// verify if data is complete
		if($lati && $longi && $formatted_address){
		 
			// put the data in the array
			$data_arr = array();            
			 
			array_push(
				$data_arr, 
					$lati, 
					$longi, 
					$formatted_address
				);
			 
			return $data_arr;
			 
		}else{
			return false;
		}
		 
	}else{
		return false;
	}
}

// -----------------------------------------------------------------------------------------------------
// AUTHENICATION FUNCTIONS
// -----------------------------------------------------------------------------------------------------

// Registers the user, takes everything as strings
function register($username, $firstname, $lastname, $password, $email, $facebookId) {
	// Ensure facebook username space is not being taken
	if (startsWith($username, "FacebookUser")) {
		die("Username is reserved for Facebook logins");
	}

	$password =  password_hash($password, PASSWORD_DEFAULT);

	$sql = "INSERT INTO users (username, password, email, facebookId, firstname, lastname, datecreated) 
		VALUES ('$username', '$password', '$email', '$facebookId', '$firstname', '$lastname', '".date("Y-m-d H:i:s")."');";
	$result = query ($sql);

	return $result;
}

// Registers the user if they are loging in with facebook
function handleFacebookTokenRegistration($facebookToken) {
	$fb = new Facebook\Facebook([
		'app_id' => FACEBOOK_APP_ID,
		'app_secret' => FACEBOOK_APP_SECRET,
		'default_graph_version' => FACEBOOK_DEFAULT_GRAPH_VERSION,
		]);

	try {
		// Returns a `Facebook\FacebookResponse` object
		$response = $fb->get('/me?fields=id,first_name,last_name', $facebookToken);
	} catch(Facebook\Exceptions\FacebookResponseException $e) {
		$value = 'Graph returned an error: ' . $e->getMessage();
		exit;
	} catch(Facebook\Exceptions\FacebookSDKException $e) {
		$value = 'Facebook SDK returned an error: ' . $e->getMessage();
		exit;
	}

	$user = $response->getGraphUser();

	$firstname = $user->getFirstName();
	$lastname = $user->getLastName();
	$facebookId = $user['id'];
	$username = "FacebookUser".$facebookId;

	$sql = "INSERT INTO users (firstname, lastname, facebookId, username, datecreated) 
		VALUES ('$firstname', '$lastname', '$facebookId', '$username', '".date("Y-m-d H:i:s")."');";
	$result = query ($sql);

	return $result;
}

// Login, takes the username and password as strings
function login($username, $password) {
	$results = getUser($username);

	if ($results == null) {
		header("HTTP/1.1 404 Not Found");
    		exit;
	}

	if ($results["facebookId"]) {
		header("HTTP/1.1 403 Forbidden: Please use facebook login");
    		exit;
	}

	$storedPassword = $results["password"];

	if (password_verify($password, $storedPassword)) {
		$authID = password_hash("cookie-".$username.$storedPassword.AUTH_SALT, PASSWORD_DEFAULT);

		setcookie('collegepartyauth[user]', $username, 0, '/');
		setcookie('collegepartyauth[authID]', $authID, 0, '/');

		return "Successfully Logged In";
	} else {
		header("HTTP/1.1 403 Forbidden");
    		exit;
	}

}

// Login using facebook, takes a facebook token.
function loginFacebook($facebookToken) {
	$fb = new Facebook\Facebook([
		'app_id' => FACEBOOK_APP_ID,
		'app_secret' => FACEBOOK_APP_SECRET,
		'default_graph_version' => FACEBOOK_DEFAULT_GRAPH_VERSION,
		]);

	try {
		// Returns a `Facebook\FacebookResponse` object
		$response = $fb->get('/me?fields=id,name', $facebookToken);
	} catch(Facebook\Exceptions\FacebookResponseException $e) {
		exit($e->getMessage());
		header("HTTP/1.1 403 Forbidden");
    		exit;
	} catch(Facebook\Exceptions\FacebookSDKException $e) {
		exit($e->getMessage());
		header("HTTP/1.1 403 Forbidden");
    		exit;
	}

	$user = $response->getGraphUser();

	$username = "FacebookUser".$user["id"];

	$results = getUser($username);

	if ($results == null) {
		header("HTTP/1.1 404 Not Found");
    		exit;
	}

	$authID = password_hash("cookie-".$username.AUTH_SALT, PASSWORD_DEFAULT);

	setcookie('collegepartyauth[user]', $username, 0, '/');
	setcookie('collegepartyauth[authID]', $authID, 0, '/');

	return $results;
}

// Checks the users login. Should be done before all functions
function checkLogin() {
	// Checking for this variable
	$cookie;

	// Check that the auth cookie is set, if it is, grab it
	if (isset($_COOKIE['collegepartyauth'])) {
		$cookie = $_COOKIE['collegepartyauth'];
	}

	// Ensure the cookie is not empty
	if (!empty($cookie)) {
		$username = $cookie['user'];
		$authID = $cookie['authID'];

		if (startsWith($username, 'FacebookUser')) {
			return checkLoginFacebook($username, $authID);
		}

		getUser($username);

		$storedPassword = $results["password"];

		if (!password_verify("cookie-".$username.$storedPassword.AUTH_SALT, $authID)) {
			header("HTTP/1.1 403 Forbidden");
    			exit;
		}

		return true;
	} else {
		header("HTTP/1.1 401 Unauthorized");
    		exit;
	}
}

// Checks the user's login if they logged in with facebook
function checkLoginFacebook($username, $authID) {
	getUser($username);

	if (!password_verify("cookie-".$username.AUTH_SALT, $authID)) {
		header("HTTP/1.1 403 Forbidden");
    		exit;
	}

	return true;
}

// Logout, logs the user out by overriding their cookies and making them expire
function logout() {
	$idout = setcookie('collegepartyauth[authID]', '', -3600, '', '', '', true);
	$userout = setcookie('collegepartyauth[user]', '', -3600, '', '', '', true);
	
	if ( $idout == true && $userout == true ) {
		return true;
	} else {
		return false;
	}
}

// Gets the username from the passed cookie
function getCookieUsername() {
	// Checking for this variable
	$cookie;

	// Check that the auth cookie is set, if it is, grab it
	if (isset($_COOKIE['collegepartyauth'])) {
		$cookie = $_COOKIE['collegepartyauth'];
	}

	$username = null;

	if (!empty($cookie)) {
		$username = $cookie['user'];
	}

	return $username;
}

// Gets the ID of a user by requesting it from the database
function getUserId($username) {
	$result = getUser($username);

	return $result['id'];
}

?>
