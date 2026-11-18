import "pe"
import "math"

// invented rules
rule Dropper_10
{
    meta:
        author = "Example Team"
        description = "Invented rule 10"
        date = "2026-02-11"
    strings:
        $r0 = /pass(word)?=/
        $s1 = "xyz"
        $h2 = { CF 14 }
    condition:
        any of them
}

rule Stealer_11
{
    meta:
        author = "Example Team"
        description = "Invented rule 11"
        date = "2026-02-11"
    strings:
        $s0 = "http://example.test/p" fullword
        $h1 = { AF E5 2E 56 D5 AE }
        $r2 = /https?:\/\/[a-z]+\.test/i
    condition:
        $s0
}

rule Stealer_12
{
    meta:
        author = "Example Team"
        description = "Invented rule 12"
        reference = "https://example.test/r/12"
    strings:
        $h0 = { 74 3B BE 05 61 CD [2-4] 4F A9 }
    condition:
        all of them
}
