<?php

session_start();
if (!isset($_SESSION['username'])) {
    header('location: ../guest/index.php');
}
else{ 
    if ($_SESSION['status'] != "admin") {
        header('location: ../user/index.php');
    }
}

// $list = $_SESSION['list'];
// $total = $_SESSION['total'];
include('userlist.php');


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>

    <link rel="stylesheet" href="../css/index.css">
    <link rel="stylesheet" href="../css/users.css">
    <link href='https://fonts.googleapis.com/css?family=Arimo' rel='stylesheet'>

    <!-- Archivos CSS -->
    <link rel=" stylesheet " href="../css/bootstrap.min.css ">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">

    <link rel="stylesheet" href="../css/moviesrequest.css">

    <link rel="stylesheet" href="../css/popup.css">
</head>
<body background="...\image\fondo.jgp">
    <nav class="navbar navbar-expand-sm bg-secondary navbar-dark fixed-top ">
        <!-- Logo -->
        <a class="navbar-brand " href="index.php">
        <img src="../image/8.png " alt="logo "> Cinema
        </a>

        <!-- Links -->
        <ul class="navbar-nav mr-auto ">
        </ul>
        <!-- Links -->
        <ul class="navbar-nav ">
            <li class="nav-item ">
                <a class="nav-link active " href="index.php "> ✷ Inicio</a>
            <li class="nav-item ">
                <!-- <li class="nav-item ">
                <a class="nav-link" href="moviesrequest.php"> | Movies Request Pending</a>
            </li>
            </li> -->
            <li class="nav-item ">
                <a class="nav-link " href=""> ✷ Ingresar proyecciones</a>
            </li>
            </li> 
            <li class="nav-item ">
                <a class="nav-link " href="users.php"> ✷ Gestionar usuarios</a>
            </li>
            </li> 
            <li class="nav-item ">
                <a class="nav-link" href="admincinema.php"> ✷ Administrar cines</a>
            </li>
            <li class="nav-item ">
                <a class="nav-link" href=""> ✷ Stock entradas</a>
            </li>
            <li class="nav-item ">
                <a class="nav-link" href=""> ✷ Dinero recaudado</a>
            </li>

            <li class="nav-item dropdown dropleft">
                <a class="nav-link" href="#" data-toggle="dropdown">
                    <img src="../image/default-user.png" style="width:30px; border-radius:50%;" alt="logo ">
                </a>
                <div class="dropdown-menu">
                    <a class="dropdown-item disabled" style="color:silver; text-transform:lowercase;" href="#"><?php echo $_SESSION['username'] ?></a>
                    <a class="dropdown-item" style="color:#fff;" href="../controller/logout.php">Cerrar Sesion</a>
                </div>
            </li>
        </ul>
    </nav>

    <div class="container req-box" >
        <form action="" method="post">
            <div class="row">
                <div class="col-md-10 box1">
                    <h3 style="margin-bottom:50px;"><span style="font-weight:bold; color: yellow">Lista de usuarios </span>(<?php echo $total ?>)</h3>
                    <?php 
                    echo $list;
                    ?>
                    <a href="#popup2" class="btn"> Agregar nueva cuenta</a>
                </div>
            </div>   
        </form>
    </div>

    <div id="popup2" class="popup-overlay">
        <div class="log-popup">
            <h2>Agregar nueva cuenta</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
                <form action="../controller/register.php" method="post">
                    <i class="fa fa-user icon"></i>
                    <input type="text" placeholder="Nombre y Apellido" name="fullname" class="log-input" required>
                    <br>
                    <i class="fa fa-envelope icon"></i>
                    <input type="email" placeholder="Email" name="email" class="log-input" required>
                    <br>
                    <i class="fa fa-link icon"></i>
                    <input type="text" placeholder="Nombre de Usuario" name="username" class="log-input" required>
                    <br>
                    <i class="fa fa-lock icon"></i>
                    <input type="password" placeholder="Contraseña" name="password" class="log-input" required>
                    <br>
                    <input type="submit" value="Sign Up" name="signup-btn" class="btn-log">
                </form>
            </div>
        </div>
    </div>
    <div id="success" class="popup-overlay">
        <div class="log-popup">
            <h2>Success</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
               <p style="color:black">La cuenta se creo existosamente</p> 
            </div>
        </div>
    </div>
    <div id="updatesuccess" class="popup-overlay">
        <div class="log-popup">
            <h2>Success</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
               <p style="color:black">Usuario editado correctamente :)</p> 
            </div>
        </div>
    </div>
    <div id="error" class="popup-overlay">
        <div class="log-popup">
            <h2>Error</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
               <p style="color:black">El usuario o email no existe :( Por favor, intenta nuevamente</p> 
            </div>
        </div>
    </div>

    <!-- jQuery library -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <!-- Popper JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.0/umd/popper.min.js"></script>

    <!-- Latest compiled JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js"></script>
</body>
</html>