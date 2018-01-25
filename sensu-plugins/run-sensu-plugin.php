#!/usr/bin/php
<?php

use Ossec\SensuServer\Command\OssecAlert;
use Symfony\Component\Console\Application;

require_once __DIR__ . '/vendor/autoload.php';

if(ini_get('date.timezone') == null) {
  ini_set('date.timezone', 'UTC');
}

$console = new Application();
$console->add(new OssecAlert());
$console->run();

