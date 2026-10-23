<?php
header('Content-Type: text/plain');
echo "peak=" . memory_get_peak_usage(true) . "\n";
echo "files=" . count($_FILES) . "\n";
echo "post_keys=" . count($_POST) . "\n";
echo "memlimit=" . ini_get('memory_limit') . " postmax=" . ini_get('post_max_size') . " nesting=" . ini_get('max_input_nesting_level') . " parts=" . ini_get('max_multipart_body_parts') . "\n";
