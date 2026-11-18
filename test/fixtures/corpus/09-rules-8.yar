import "math"

// invented rules
rule Stealer_80
{
    meta:
        author = "Example Team"
        description = "Invented rule 80"
        mitre_attack = "T1486"
    strings:
        $s0 = "xyz" nocase
        $h1 = { 56 1E B5 E6 2F D3 [2-4] A1 6F }
        $r2 = /pass(word)?=/
        $s3 = "ab" nocase
        $h4 = { E7 B9 }
    condition:
        $s0 and $h1 and $r2 and $s3 and $h4
}
