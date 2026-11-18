import "pe"
import "math"

// invented rules
rule Webshell_30
{
    meta:
        author = "Example Team"
        description = "Invented rule 30"
        date = "11.02.2026"
        reference = "https://example.test/r/30"
    strings:
        $s0 = "cmd.exe /c"
        $h1 = { D3 A4 3E 7C 04 40 }
    condition:
        $s0 and $missing
}

rule Stealer_31
{
    meta:
        author = "Example Team"
        description = "Invented rule 31"
        date = "11.02.2026"
        reference = "https://example.test/r/31"
        mitre_attack = "T1055"
    strings:
        $h0 = { 00 99 BF AF 0E C7 }
        $s1 = "http://example.test/p" nocase
    condition:
        any of them
}

rule Webshell_32
{
    meta:
        author = "Example Team"
    strings:
        $r0 = /.*evil[0-9]+/i
        $h1 = { 9F 1A }
        $h2 = { 43 D1 35 9A 48 17 [2-4] 24 55 ( 01 | 02 ) ??  }
        $r3 = /https?:\/\/[a-z]+\.test/
        $s4 = "GetProcAddress"
    condition:
        $r0 and $missing
}

rule Loader_33
{
    meta:
        author = "Example Team"
        description = "Invented rule 33"
        date = "11.02.2026"
    strings:
        $r0 = /pass(word)?=/i
        $r1 = /.*evil[0-9]+/is
        $r2 = /.*evil[0-9]+/is
        $h3 = { 25 9E 67 14 C1 D6 }
        $s4 = "xyz" ascii
    condition:
        all of them
}

rule Webshell_34
{
    meta:
        author = "Example Team"
        description = "Invented rule 34"
    strings:
        $r0 = /pass(word)?=/i
    condition:
        uint16(0) == 0x5A4D and $r0
}
