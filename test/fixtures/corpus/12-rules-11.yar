import "pe"

// invented rules
rule Ransom_110
{
    meta:
        author = "Example Team"
        reference = "https://example.test/r/110"
    strings:
        $h0 = { D2 4A A7 94 04 CA [2-4] B6 29 }
        $h1 = { DB CF }
        $s2 = "xyz" nocase
    condition:
        2 of ($h*)
}
