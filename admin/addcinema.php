<?php

   session_start();

   include('../controller/connectdb.php');

   $capacity=$_POST['capacity'];
   $address = $_POST['address'];
   $cineName = strtolower($_POST['cineName']);
   $ticketPrice = $_POST['ticketPrice'];

    //Validation
    $q = "SELECT * FROM cinema WHERE cineName = '$cineName'";

    $res = $conn->query($q);
    $num = mysqli_num_rows($res);  

    if ($num >= 1) {
        if ($_SESSION['username']=="admin") {
            header('location: ../users/index.php#error');
        } else {
            header('location: ../guest/index.php#error');
        }
    } else {
        $sql = "INSERT INTO cinema (capacity, address, cineName,ticketPrice) values('$capacity','$address','$cineName','$ticketPrice')";

        $result = $conn -> query($sql);

        if ($_SESSION['username']=="admin") {
            header('location: ../admin/admincinema.php#success');
        } else {
            header('location: ../guest/index.php#success');
        }     
    }
    $conn->close();
?>
<!-- Crear nuevo cine-->