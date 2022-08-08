
<?php
session_start();
if (isset($_SESSION['username'])) {
    if ($_SESSION['status'] == "admin") {
        header('location: ../admin/index.php');
    } else {
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
    <title>Bienvenidos a Cinema Movies </title>
    <link rel="stylesheet" href="../css/index.css">
    <link href='https://fonts.googleapis.com/css?family=Arimo' rel='stylesheet'>

    <!-- Latest compiled and minified CSS -->
    <link rel=" stylesheet " href="../css/bootstrap.min.css ">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">

    <link rel="stylesheet" href="../css/popup.css">

</head>

<body>
<nav class="navbar navbar-expand-sm bg-secondary navbar-dark fixed-top ">
             <!-- Logo -->
             <a class="navbar-brand text-danger" href="index.php">
        <img src="../image/8.png " alt="logo "> <strong> CINEMA UNL</strong>
        </a>

        <!-- Links -->
        <ul class="navbar-nav mr-auto">

        </ul>
        <!-- Links -->
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link active text-white" href="#">✷ Inicio</a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white" href="browse.php">✷ Buscar Peliculas </a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white" href="#popup1">✷ Iniciar Sesion</a>
            </li>
        </ul>
    </nav>

    <!-- Iniciar sesion y registro -->
    <div id="popup1" class="popup-overlay">
        <div class="log-popup">
            <h2>Iniciar Sesion</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
                <form action="../controller/login.php" method="post">
                    <i class="fa fa-user icon"></i>
                    <input type="text" placeholder="Usuario" name="username" class="log-input" required>
                    <br>
                    <i class="fa fa-lock icon"></i>
                    <input type="password" placeholder="Contraseña" name="password" class="log-input" required>
                    <br>
                    <input type="submit" value="Iniciar sesion" name="signup-btn" class="btn-log">
                </form>
            </div>
        </div>
    </div>

    <div id="popup2" class="popup-overlay">
        <div class="log-popup">
            <h2>Registrarse</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
                <form action="../controller/register.php" method="post">
                    <i class="fa fa-user icon"></i>
                    <input type="text" placeholder="Ingresa tu nombre" name="fullname" class="log-input" required>
                    <br>
                    <i class="fa fa-envelope icon"></i>
                    <input type="email" placeholder="Ingresa tu email" name="email" class="log-input" required>
                    <br>
                    <i class="fa fa-link icon"></i>
                    <input type="text" placeholder="Ingresa un usuario" name="username" class="log-input" required>
                    <br>
                    <i class="fa fa-lock icon"></i>
                    <input type="password" placeholder="Contraseña" name="password" class="log-input" required>
                    <br>
                    <input type="checkbox" name="chkbox" required>Acepto los terminos y condiciones*
                    <br>
                    <input type="submit" value="Registrarse" name="signup-btn" class="btn-log">
                </form>
            </div>
        </div>
    </div>
    <div id="success" class="popup-overlay">
        <div class="log-popup">
            <h2>Nuevo Usuario</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
                <p>La cuenta se creo correctamente :) </p>
                <a href="#popup1" class="btn-main btn-main-primary">
                        Iniciar Sesion
                </a>
            </div>
        </div>
    </div>
    <div id="error" class="popup-overlay">
        <div class="log-popup">
            <h2>Error</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
                <p>El usuario o email no existe, intenta nuevamente</p>
            </div>
        </div>
    </div>
    <div id="error1" class="popup-overlay">
        <div class="log-popup">
            <h2>Error</h2>
            <a class="close-window" href="#">&times;</a>
            <div class="log-content">
                <p>No se encontro ninguna cuenta. Intenta nuevamente </p>
            </div>
        </div>
    </div>
    <!-- End of Pop up boxes for login and registration -->



    <header>
        <div class="container body ">
            <center>
                <div class="inner-body ">
                    <h1 class="title "><span style="color:white">Bienvenido a</span> 
                        <span style="color: red "> ★ Cinema ★</span>
                    </h1>
                    <br>
                   <h3> <p style="color: white">
                               En este sitio podras comprar entradas para peliculas en estreno en la ciudad de Mar del Plata. Aqui encontraras toda la
                                <span style="font-weight:bold; color: red">Informacion</span> de cada pelicula y saber en que cines se proyecta cada film. Gracias a la colaboracion de
                                <span style="font-weight:bold; color: red"> MovieDB </span> podras ver la Informacion de todas y cada una de las peliculas estrenadas y no estrenadas. 
                                
                            </p></h3>
                </div>
                <div class="container">
                    <a href="#popup1" class="btn-main btn-main-primary">
                        Iniciar Sesion
                    </a>
                    <a href="#popup2" class="btn-main">
                        Registrarse
                    </a>
                </div>

            </center>
        </div>
    </header>

    <div class="about-box bg-secondary ">
        <center>
            <div class="about ">
                <h1>Acerca de este sitio</h1>
                <p class="about-content ">Lorem ipsum dolor sit amet consectetur adipisicing elit. Voluptate nobis officiis, labore non molestias maxime,
                    corporis saepe voluptatibus culpa sequi minus vitae qui eos expedita quos placeat consectetur voluptas
                    ullam. Lorem ipsum dolor sit amet, consectetur adipisicing elit. Necessitatibus quos, aut voluptatum
                    a est distinctio cumque eveniet nisi. Soluta, aliquid tempora quae in reiciendis aut aliquam obcaecati
                    atque dolor perspiciatis?</p>
            </div>
        </center>
    </div>

   <div id="demo" class="carousel slide container" data-ride="carousel">
        <div class="ratedMoviesHead">
            <h1>Top Peliculas</h1>
        </div>
        <!-- Indicators -->
        <ul class="carousel-indicators">
            <li data-target="#demo" data-slide-to="0" class="active"></li>
            <li data-target="#demo" data-slide-to="1"></li>
            <li data-target="#demo" data-slide-to="2"></li>
            <li data-target="#demo" data-slide-to="3"></li>
            <li data-target="#demo" data-slide-to="4"></li>
        </ul>

        <!-- The slideshow -->
        <div class="carousel-inner">
            <div class="carousel-item active">
                <div id="topMovies1" class="row"></div>
            </div>
            <div class="carousel-item">
                <div id="topMovies2" class="row"></div>
            </div>
            <div class="carousel-item">
                <div id="topMovies3" class="row"></div>
            </div>
            <div class="carousel-item">
                <div id="topMovies4" class="row"></div>
            </div>
            <div class="carousel-item">
                <div id="topMovies5" class="row"></div>
            </div>
        </div>

        <!-- Left and right controls -->
        <a class="carousel-control-prev" href="#demo" data-slide="prev">
            <span class="carousel-control-prev-icon"></span>
        </a>
        <a class="carousel-control-next" href="#demo" data-slide="next">
            <span class="carousel-control-next-icon"></span>
        </a>
    </div>

    <div class="footer">
    <p>&copy; Copyright Carlos Ordoñez UNL.</p>
    </div>
    <!-- jQuery library -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <!-- Popper JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.0/umd/popper.min.js"></script>

    <!-- Latest compiled JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js"></script>

    <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
        crossorigin="anonymous"></script>
    <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
    <script src="../js/main.js"></script>
    <script>
        getTopMovies();
    </script>
</body>

</html>