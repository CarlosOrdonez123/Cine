<?php

session_start();
if (!isset($_SESSION['username'])) {
    header('location: ../guest/index.php');
} else {
    if ($_SESSION['status'] == "admin") {
        header('location: ../admin/index.php');
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Informacion de peliculas</title>

    <link rel="stylesheet" href="../css/movie.css">
    <link href='https://fonts.googleapis.com/css?family=Arimo' rel='stylesheet'>

    <!-- Archivos CSS -->
    <link rel="stylesheet" href="../css/bootstrap.min.css">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
</head>

<body>

    <nav class="navbar navbar-expand-sm bg-secondary navbar-dark fixed-top ">
        <!-- Logo -->
        <a class="navbar-brand text-danger" href="index.php">
            <img src="../image/8.png " alt="logo "> <strong> CINEMA</strong>
        </a>
        <!-- Links -->
        <ul class="navbar-nav mr-auto">

        </ul>
        <!-- Links -->
        <ul class="navbar-nav">
            <li class="nav-item text-white">
                <a class="nav-link active text-white " href="index.php"> ✷ Inicio</a>
            <li class="nav-item ">
            <li class="nav-item">
                <a class="nav-link active text-white" href="browse.php">✷ Buscar peliculas</a>
            </li>
            <li class="nav-item dropdown dropleft">
                <a class="nav-link text-white" href="#" data-toggle="dropdown">
                    <img src="../image/default-user.png" style="width:30px; border-radius:50%;" alt="logo ">
                </a>
                <div class="dropdown-menu">
                    <a class="dropdown-item disabled" style="color:silver; text-transform:lowercase;" href="#"><?php echo $_SESSION['username'] ?></a>
                    <a class="dropdown-item" style="color:#fff;" href="../controller/logout.php">Cerrar Sesion</a>
                </div>
            </li>
        </ul>
    </nav>


    <div class="container">
        <div class="movie" id="movie"></div>
        <a id="" href="">
            <button class="movie-B">Comprar entradas</button>
        </a>
    </div>
    <div class="container">
        <div class="container main-review">
            <h1 class="title-second review-text">Reseñas</h1>
            <div id="reviews"></div>
        </div>
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

    <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>
    <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
    <script src="../js/main.js"></script>
    <script>
        getMovie();
        getReviews();
    </script>
</body>

</html>