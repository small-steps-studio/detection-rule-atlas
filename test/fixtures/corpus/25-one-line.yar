rule Ransom_900 { strings: $s0 = "GetProcAddress" ascii $h1 = { FD 78 26 C4 9C F1 ( 01 | 02 ) ??  } $s2 = "ab" $h3 = { A9 2C } $h4 = { 27 88 48 05 83 C7 ( 01 | 02 ) ??  } condition: $s0 and $missing }
rule Stealer_901 : T1505_003 { strings: $h0 = { D9 3B F1 2E 2C 0C } condition: $h0 and $missing }
rule Webshell_902 : T1505_003 { strings: $s0 = "http://example.test/p" fullword $r1 = /pass(word)?=/i condition: uint16(0) == 0x5A4D and $s0 }
