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


?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Bienvenido a Cinema</title>
    <link rel="stylesheet" href="../css/index.css">
    <link href='https://fonts.googleapis.com/css?family=Arimo' rel='stylesheet'>

    <!-- Archivos CSS -->
    <link rel=" stylesheet " href="../css/bootstrap.min.css ">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="../css/popup.css">

</head>

<body> 
      <nav class="navbar navbar-expand-sm bg-secondary navbar-dark fixed-top">  <!--navbar navbar-expand-sm bg-secondary navbar-dark fixed-top-->
        <!-- Logo -->
        <a class="navbar-brand text-danger " href="index.php">
        <img src="../image/8.png " alt="logo "> <strong> CINEMA</strong>
        </a>

        <!-- Links --> 
        <ul class="nav-nav mr-auto"> 
        </ul>
        
        <ul class="navbar-nav">
            <li class="nav-item text-white">
                <a class="nav-link active text-white " href="index.php"> ✷ Inicio</a>
            <li class="nav-item ">
                <a class="nav-link text-white" href="process.php"> ✷ Ingresar proyecciones</a>
            </li>
            </li> 
            <li class="nav-item ">
                <a class="nav-link text-white " href="users.php"> ✷ Gestionar usuarios</a>
            </li>
            </li> 
            <li class="nav-item ">
                <a class="nav-link text-white " href="admincinema.php"> ✷ Administrar cines</a>
            </li>
            <li class="nav-item ">
                <a class="nav-link text-white" href="process.php"> ✷ Stock entradas</a>
            </li>
            <li class="nav-item ">
                <a class="nav-link text-white" href="process.php"> ✷ Dinero recaudado</a>
            </li>

            <li class="nav-item dropdown dropleft ">
                <a class="nav-link text-white " href="#" data-toggle="dropdown"> ✷ Cuenta
                    <img src="../image/default-user.png" style="width:30px; border-radius:50%;" alt="logo ">
                </a>
                <div class="dropdown-menu">
                    <a class="dropdown-item disabled" style="color:silver; text-transform:lowercase;" href="#"><?php echo $_SESSION['username'] ?></a>
                    <a class="dropdown-item" style="color:#fff;" href="../controller/logout.php">Cerrar Sesion</a>
                </div>
            </li>
        </ul>
    </nav>
    <header>
        <div class="container body ">
            <center>
                <div class=" inner-body ">
                    <h1 class="title ">★ Cinema ★<br>
                        <span style="color: yellow;">Panel de Administrador</span>
                    </h1>
                    <p style="color: white" class="content">
                       Bienvenido a 
                        <span style="font-weight:bold; color: yellow">Cinema</span> | En esta seccion podras administrar la informacion de cada 
                        cine y proyeccion.</span> Con la ayuda de la pagina de 
                        <span style="font-weight:bold; color: yellow">MovieDB </span> podras obtener una amplia lista de peliculas para utilizar en tu 
                        <span style="font-weight:bold; color: yellow">Cartelera de cine.</span> 
                    </p>
                </div>
                <div class="container">
                    <a href="process.php" class="btn-main ">
                        Ingresar proyecciones
                    </a>
                    <a href="users.php" class="btn-main ">
                        Gestionar Usuarios
                        </a>
                    </a>
                     <a href="admincinema.php" class="btn-main ">
                        Administrar cines
                    </a> <br> <br>
                    <a href="process.php" class="btn-main ">
                        Stock entradas
                    </a>
                    <a href="process.php" class="btn-main ">
                        Dinero recaudado
                    </a>
                </div>

            </center>
        </div>
    </header>
    </body>


    
    <div class="footer">
        
    <p>&copy; Copyright Carlos Ordoñez UNL.</p>
    </div>
    <!-- jQuery library -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <!-- Popper JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.0/umd/popper.min.js"></script>

    <!-- Latest compiled JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js"></script>



</html>