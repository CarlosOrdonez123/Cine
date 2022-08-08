<?php
include('../controller/connectdb.php');

//Validacion
$sql = "SELECT * FROM cinema"; 
$result = $conn->query($sql);
$list = '';
$total = $result->num_rows;

if($result->num_rows > 0) {
    // output data of each row
     while($row = $result->fetch_assoc()) {
        $list = $list.'
        <div class="row box">
        <div class="col-md-2 box4">
         <img src="../image/logoCine.jpg" alt="user" class="user-profile">
        </div>
        <div class="col-md-6 box5">
            <p> <span style="color: #9a9a9a;">Nombre: </span> '.$row["cineName"].'<br>
             <span style="color: #9a9a9a;">Dirección: </span>'.$row["address"].'<br>
           <span style="color: #9a9a9a;">Capacidad: </span>'.$row["capacity"].'<br>
           <p> <span style="color: #9a9a9a;">Precio $: </span> '.$row["ticketPrice"].'
            </p>
        </div>
        <div class="col-md-4 box5">
            <a href="../controller/deleteCinema.php?id='.$row["cinemaid"].'" class="btn btn-danger"> Borrar </a>
            <a href="updatecinema.php?id='.$row["cinemaid"].'" class="btn"> Editar </a>
        </div>
    </div>            
        ';
    }
    
} else {
    $list = "There is no cinema created yet";
}

// $_SESSION['list']= $list;
// $_SESSION['total']= $total;


$conn->close();
?>