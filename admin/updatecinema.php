
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

include('../controller/connectdb.php');

$id=$_REQUEST['id'];
$query = "SELECT * from cinema where cinemaid='$id'"; 
$r = $conn -> query($query);
$row = $r->fetch_assoc();

if (isset($_POST['update'])) {
    $capacity=$_POST['capacity'];
    $address = $_POST['address'];
    $cineName = strtolower($_POST['cineName']);
    $ticketPrice = $_POST['ticketPrice'];

    //Validation
    $q = "SELECT * FROM cinema WHERE cineName = '$cineName'";

    $res = $conn->query($q);
    $num = mysqli_num_rows($res);  

    if ($num > 1) {
            echo "error";
            header('location: admincinema.php#error');
    } else {
        //$sql = "INSERT INTO cinema (cineName,ticketPrice,capacity,address) values('$username','$ticketPrice','$capacity','$address')";

        $sql = "UPDATE cinema SET capacity='$capacity',cineName='$cineName',ticketPrice = '$ticketPrice', address='$address' WHERE cinemaid='$id'";

        $result = $conn -> query($sql);

            header('location: admincinema.php#updatecinesuccess');  
    }
}

    

    
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
    <link href='https://fonts.googleapis.com/css?family=Arimo' rel='stylesheet'>

    <!-- Archivos CSS -->
    <link rel=" stylesheet " href="../css/bootstrap.min.css ">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="../css/popup.css">
    <link rel="stylesheet" href="../css/request.css">

</head>
<body>
    <nav class="navbar navbar-expand-sm bg-secondary navbar-dark fixed-top ">
       <!-- Logo -->
       <a class="navbar-brand " href="index.php">
        <img src="../image/2.png " alt="logo "> <strong> CINEMA</strong>
        </a>

        <!-- Links -->
        <ul class="navbar-nav mr-auto ">
        </ul>
        <!-- Links -->
        <ul class="navbar-nav ">
            <li class="nav-item ">
                <a class="nav-link active " href="index.php "> ✷ Inicio</a>
            <li class="nav-item ">
        <li class="nav-item ">
                <a class="nav-link " href=""> ✷ Ingresar proyecciones</a>
            </li>
            </li> 
            <li class="nav-item ">
                <a class="nav-link " href="users.php"> ✷ Gestionar usuarios</a>
            </li>
            </li> 
            <li class="nav-item ">
                <a class="nav-link" href=""> ✷ Administrar cines</a>
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
                    <a class="dropdown-item" style="color:#fff;" href="../controller/logout.php">Cerrar sesion</a>
                </div>
            </li>
        </ul>
    </nav>

    <header>
        <div class="container req-box" >
        <center><h3 style="margin-bottom:50px;"><span style="font-weight:bold; color: red">Modificar Informacion de Cine</span></h3></center>
            <form action="" method="post">
                <div class="row">
                    <div class="col-md-6 box1">
                        <label for="title">Nombre:</label><br>
                        <input type="text" name="cineName" class="input" value="<?php echo $row['cineName'];?>" required><br>                      
                        <label for="title">Dirección:</label><br>
                        <input type="address" name="address" class="input" value="<?php echo $row['address'];?>" required><br>
                    
                    </div>
                    <div class="col-md-6 box1">
                        <label for="title">Capacidad:</label><br>
                        <input type="text" name="capacity" class="input" value="<?php echo $row['capacity'];?>" required  ><br>
                        <label for="title">Precio:</label><br>
                        <input type="text" name="ticketPrice" class="input" value="<?php echo $row['ticketPrice'];?>" required><br>
                        <input type="submit"  class="btn" name="update" value="Actualizar informacion de Cine">
                    </div>
                </div>   
            </form>
        </div>
    </header>

    <div class="footer">
    <p>&copy; Copyright Carlos Ordoñez UNL.</p>
    </div>
    <!-- jQuery library -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <!-- Popper JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.0/umd/popper.min.js"></script>

    <!-- Latest compiled JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js"></script>
</body>
</html>