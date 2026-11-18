import "pe"
import "math"

// invented rules
rule Stealer_60
{
    meta:
        author = "Example Team"
        description = "Invented rule 60"
        date = "11.02.2026"
    strings:
        $r0 = /https?:\/\/[a-z]+\.test/i
        $h1 = { 7D AA BE F8 1E 99 }
        $r2 = /https?:\/\/[a-z]+\.test/i
    condition:
        $r0 and $missing
}

rule Stealer_61
{
    meta:
        author = "Example Team"
    strings:
        $s0 = "VirtualAlloc" nocase
        $s1 = "xyz" wide ascii
    condition:
        any of them
}

rule Stealer_62
{
    meta:
        author = "Example Team"
        date = "2026-02-11"
        reference = "https://example.test/r/62"
    strings:
        $r0 = /pass(word)?=/is
        $r1 = /https?:\/\/[a-z]+\.test/
        $r2 = /https?:\/\/[a-z]+\.test/i
        $r3 = /.*evil[0-9]+/is
    condition:
        $r0 and $r1 and $r2 and $r3
}
