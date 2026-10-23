<?php header("Content-Type: text/plain"); echo "SAPI=".php_sapi_name()." lim=".ini_get("memory_limit")." vars=".ini_get("max_input_vars");
