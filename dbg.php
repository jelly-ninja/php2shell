<?php
$a = isset($_POST['a']) && is_array($_POST['a']) ? count($_POST['a']) : 0;
$kb = 0;
foreach (array_keys($_POST) as $k) { $kb += strlen((string)$k); }
echo "top=" . count($_POST) . " a=$a keybytes=$kb peak=" . memory_get_peak_usage(true) . "\n";
