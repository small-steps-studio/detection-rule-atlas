rule Hex { strings: $a = { 4D 5A } $b = { 4D 5A [4-6] 50 45 00 00 } $c = { ( 6A 40 | 68 00 30 ) ?? ?? 00 } $d = { 4D ZZ 5A } $e = "" condition: any of them }
