<?php
// db.php

$servername = "192.168.241.254";
$username = "app";
$password = "securepass";      
$dbname = "users"; 

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>