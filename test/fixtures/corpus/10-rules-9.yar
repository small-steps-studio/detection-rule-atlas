import "pe"
import "math"

// invented rules
rule Webshell_90 : webshell
{
    meta:
        author = "Example Team"
        description = "Invented rule 90"
        date = "2026-02-11"
    strings:
        $h0 = { 91 23 79 C4 30 10 }
        $r1 = /.*evil[0-9]+/is
        $h2 = { 96 65 4A 62 85 C8 }
        $s3 = "GetProcAddress" ascii
    condition:
        $h0 and $r1 and $h2 and $s3
}

rule Dropper_91
{
    meta:
        author = "Example Team"
        date = "2025/12/01"
        reference = "https://example.test/r/91"
    strings:
        $s0 = "cmd.exe /c"
        $r1 = /https?:\/\/[a-z]+\.test/is
        $s2 = "VirtualAlloc" wide ascii
        $s3 = "VirtualAlloc" nocase
    condition:
        2 of ($s*)
}
