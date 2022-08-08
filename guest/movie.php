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
    <title>Informacion de peliculas</title>

    <link rel="stylesheet" href="../css/movie.css">

    <!-- Archivos  CSS -->
    <link rel="stylesheet" href="../css/bootstrap.min.css">

    <link rel="stylesheet" href="../css/popup.css">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
</head>

<body>

    <nav class="navbar navbar-expand-sm bg-secondary navbar-dark fixed-top ">
              <!-- Logo -->
              <a class="navbar-brand text-white" href="index.php">
        <img src="../image/8.png " alt="logo "> <strong> CINEMA</strong>
        </a>
        <!-- Links -->
        <ul class="navbar-nav mr-auto">

        </ul>
        <!-- Links -->
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link text-white" href="../index.php">✷ Inicio</a>
            </li>
            <li class="nav-item">
                <a class="nav-link active text-white" href="browse.php">✷ Buscar peliculas</a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white" href="../index.php#popup1">✷ Iniciar Sesion</a>
            </li>
        </ul>
    </nav>


    <div class="container">
        <div id="movie"></div>
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

    <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
        crossorigin="anonymous"></script>
    <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
    <script src="../js/main.js"></script>
    <script>
        getMovie();
        getReviews();
    </script>
</body>

</html>