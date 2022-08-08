<?php
#MASVS-8.1 y #SER-UNTRUST
session_start();
include('connectdb.php');

    $username = $_POST['username'];
    $password = $_POST['password'];
    //Validation
    $q = "SELECT * FROM userdata WHERE Username = '$username' && Pass = '$password'";

    $res = $conn->query($q);
    $num = mysqli_num_rows($res);  

    if ($num == 1) {

       $_SESSION['username'] = strtolower($username);
        
       if ($_SESSION['username']=="admin") {
            header('location: ../admin/index.php');
            $_SESSION['status'] = 'admin';
       } else {
            header('location: ../user/index.php');
            $_SESSION['status'] = 'user';
       }
    } else {
        header('location: ../guest/index.php#error1');
    }
    $conn->close();
?>

<!--
< ?php

#Controlador inicio de Sesion
#MASVS-8.11

function logout()
{
  $_SESSION['logout'] = true;
}

function isLoggedIn()
{
  return $isLoggedIn && !$_SESSION['logout'];
}

#network-rate-limit 

limits, _ := client.GetRateLimits(ctx, WithServerSide());

# DATA-VAL
echo intval(array());                 // 0
echo intval(array('foo', 'bar'));     // 1

#CSP y RA
Content-Security-Policy: default-src 'self' *.trusted.com

#DATA-VAL
$con  = odbc_connect('localhost','root','1234','moviesinfo');
$sent = odbc_prepare($con,
      "UPDATE sesiones SET datos = ? WHERE id = ?");
$datos_sql = array (serialize($datos_sesion), $_SERVER['PHP_AUTH_USER']);

if (!odbc_execute($sent, &$datos_sql)) {
    $sent = odbc_prepare($con,
     "INSERT INTO sesiones (id, datos) VALUES(?, ?)");
    if (!odbc_execute($sent, &$datos_sql)) {
        /* Algo ha fallado.. */
    }
}

#•	MASVS-6.1 
$s = "HTTP/1.1 200 OK\r\n";
if (!preg_match('/^HTTP\/(\d\.\d)\s*(\d+).*\n/', $s, $m))
    echo "Not matched correctly!\n";
else
    echo "OK\n";


#: Require-use-strong-passwords
function generatePassword($length)
{
    $key = "";
    $pattern = "1234567890abcdefghijklmnopqrstuvwxyz";
    $max = strlen($pattern)-1;
    for($i = 0; $i < $length; $i++){
        $key .= substr($pattern, mt_rand(0,$max), 1);
    }
    return $key;
}

#SER-UNTRUST
$password = getPass;
if (md5($_POST['password']) != $password) { 
?>
<h2>Logueate</h2>
<form name="form" method="post" action="">
<input type="password" name="password"><br>
<input type="submit" value="Login"></form>
< ?php 
}else{
?>
Contenido protegido
< ?php 
} 

#LOGS-INTEGRITY
session_start();
$sessData = !empty($_SESSION['sessData'])?$_SESSION['sessData']:'';
if(!empty($sessData['status']['msg'])){
    $statusMsg = $sessData['status']['msg'];
    $statusMsgType = $sessData['status']['type'];
    unset($_SESSION['sessData']['status']);
}

#ENV-USE
// Almacenar el hash de la contraseña
$consulta  = sprintf("INSERT INTO users(name,pwd) VALUES('%s','%s');",
                pg_escape_string($nombre_usuario),
                password_hash($contraseña, PASSWORD_DEFAULT));
$resultado = pg_query($conexión, $consulta);

// Consultar si el usuario envió la contraseña correcta
$consulta = sprintf("SELECT pwd FROM users WHERE name='%s';",
                pg_escape_string($nombre_usuario));
$fila = pg_fetch_assoc(pg_query($conexión, $consulta));

if ($fila && password_verify($contraseña, $fila['pwd'])) {
    echo 'Bienvenido, ' . htmlspecialchars($nombre_usuario) . '!';
} else {
    echo 'La autenticación ha fallado para ' . htmlspecialchars($nombre_usuario) . '.';
}

//network-rate-limit
openssl_sign(
    string $data,
    string &$signature,
    mixed $priv_key_id,
    mixed $signature_alg = OPENSSL_ALGO_SHA1
): bool

//OTG-BUSLOGIC-006
oci_password_change(
    resource $connection,
    string $username,
    string $old_password,
    string $new_password
): bool

//ASSIGN-WHITE
if (!$mysqli->query("INSERT INTO test(id) VALUES (1), (2), (3), (4)")) {
    echo "Falló multi-INSERT: (" . $mysqli->errno . ") " . $mysqli->error;
}

//CWE-601
// start a session
session_start();
 
// initialize session variables
$_SESSION['logged_in_user_id'] = '1';
$_SESSION['logged_in_user_name'] = 'Tutsplus';
 
// access session variables
echo $_SESSION['logged_in_user_id'];
echo $_SESSION['logged_in_user_name'];

//CWE-525-CACHING
/* establecer el limitador de caché a 'private' */

session_cache_limiter('private');
$cache_limiter = session_cache_limiter();

echo "El limitador de caché ahora está establecido a $cache_limiter<br />";

//CWE-89-PREPARED
if (!$mysqli->query("INSERT INTO test(id) VALUES (1), (2), (3), (4)")) {
    echo "Falló multi-INSERT: (" . $mysqli->errno . ") " . $mysqli->error;
}

//ASVS-8.8
#•	MASVS-6.1 
$s = "HTTP/1.1 200 OK\r\n";
if (!preg_match('/^HTTP\/(\d\.\d)\s*(\d+).*\n/', $s, $m))
    echo "Not matched correctly!\n";
else
    echo "OK\n";

//C-MFA-FOR-PASSWORD-RECOVERY
/*
  Accept email of user whose password is to be reset
  Send email to user to reset their password
*/
if (isset($_POST['reset-password'])) {
    $email = mysqli_real_escape_string($db, $_POST['email']);
    // ensure that the user exists on our system
    $query = "SELECT email FROM users WHERE email='$email'";
    $results = mysqli_query($db, $query);
  
    if (empty($email)) {
      array_push($errors, "Your email is required");
    }else if(mysqli_num_rows($results) <= 0) {
      array_push($errors, "Sorry, no user exists on our system with that email");
    }
    // generate a unique random token of length 100
    $token = bin2hex(random_bytes(50));
  
    if (count($errors) == 0) {
      // store token in the password-reset database table against the user's email
      $sql = "INSERT INTO password_reset(email, token) VALUES ('$email', '$token')";
      $results = mysqli_query($db, $sql);
  
      // Send email to user with the token in a link they can click on
      $to = $email;
      $subject = "Reset your password on examplesite.com";
      $msg = "Hi there, click on this <a href=\"new_password.php?token=" . $token . "\">link</a> to reset your password on our site";
      $msg = wordwrap($msg,70);
      $headers = "From: info@examplesite.com";
      mail($to, $subject, $msg, $headers);
      header('location: pending.php?email=' . $email);
    }
  }

//DATA-VAL
if ( strlen( $year ) != 4 ) exit ( "$year el valor es invalido para un año!" ); 

$clean = array();
 $shell = array();

/* Filter Input ($command, $argument) */

 $shell['command'] = escapeshellcmd($clean['command']);
 $shell['argument'] = escapeshellarg($clean['argument']);
 $last = exec("{$shell['command']} {$shell['argument']}", $output, $return);

//FILE-DATA-CHECK
if (isset($_POST['submit']))
{
    if ((!isset($_POST['firstname'])) || (!isset($_POST['lastname'])) || 
        (!isset($_POST['address'])) || (!isset($_POST['emailaddress'])) || 
        (!isset($_POST['password'])) || (!isset($_POST['gender'])))
    {
        $error = "*" . "Please fill all the required fields";
    }
    else
    {
        $firstname = $_POST['firstname'];
        $lastname = $_POST['lastname'];
        $address = $_POST['address'];
        $emailaddress = $_POST['emailaddress'];
        $password = $_POST['password'];
        $gender = $_POST['gender'];
    }
}

//ASVS-11.5

//security-logging
class Test{

    private $foo;
    
    public function __construct($foo)
    {
        $this->foo = $foo;
    }
    
    private function bar()
    {
        echo 'Accessed the private method.';
    }
    
    public function baz(Test $other)
    {
        // We can change the private property:
        $other->foo = 'hello';
        var_dump($other->foo);
    
        // We can also call the private method:
        $other->bar();
    }
    }
    
    $test = new Test('test');
    $test->baz(new Test('other'));

//CSD-VAL-LOG
session_start();
if ( $_SESSION['intentos'] > 3 ) 
{ 
      $error_login = true;
}
if( !empty( $error_login ) )
{
    echo "Limite de intentos de acceso sobrepasado";
}

//CDS-USER-TRACK

// Usar import_request_variables() 
import_request_variables('p', 'p_');
echo $p_username;

echo $HTTP_POST_VARS['username'];

// Usar register_globals.
echo $username;

//LOG-TLS-FAILURES
ldap_start_tls(resource $link): bool

//EU-GDPR-LOGGING
// Establecer el límite a 5 MB.
$fiveMBs = 5 * 1024 * 1024;
$fp = fopen("php://temp/maxmemory:$fiveMBs", 'r+');

fputs($fp, "hello\n");

// Leer lo que hemos escrito.
rewind($fp);
echo stream_get_contents($fp);
?>
-->



