<?php
if(preg_match("/^[0-9]{6}$/", $_GET["id"])) {
    $user = "user_" . $_REQUEST["id"];
    $cmd = "echo $user >> users.log";
    $output = system($cmd, $return_val);
    if ($return_val === 0) {
        echo(" :) User logged successfully");
        header("HTTP/1.1 200 OK");
    } else {
        echo(" :( An error occurred!\n$cmd");
        header("HTTP/1.1 500 Internal Server Error");
    }
}else{
    echo(" :| Only 6-digit user IDs are allowed");
    header("HTTP/1.1 400 Bad Request");
}
?>
