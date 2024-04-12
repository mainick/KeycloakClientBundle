<?php

use Symfony\Component\ErrorHandler\ErrorHandler;

require dirname(__DIR__).'/vendor/autoload.php';

set_exception_handler([new ErrorHandler(), 'handleException']);
