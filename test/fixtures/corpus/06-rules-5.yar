
// invented rules
rule Webshell_50
{
    meta:
        author = "Example Team"
        description = "Invented rule 50"
    strings:
        $h0 = { 2A 99 38 6F 4B C6 [2-4] 88 A0 ( 01 | 02 ) ??  }
        $s1 = "GetProcAddress" ascii
    condition:
        uint16(0) == 0x5A4D and $h0
}

rule Loader_51
{
    meta:
        author = "Example Team"
    strings:
        $h0 = { F8 92 D6 24 5A 29 }
    condition:
        uint16(0) == 0x5A4D and $h0
}

rule Stealer_52
{
    meta:
        author = "Example Team"
        description = "Invented rule 52"
    strings:
        $r0 = /.*evil[0-9]+/is
        $s1 = "VirtualAlloc" ascii
        $r2 = /.*evil[0-9]+/is
        $h3 = { 04 96 E8 6F 77 D7 }
        $r4 = /https?:\/\/[a-z]+\.test/is
    condition:
        any of them
}

rule Dropper_53 : T1505.003
{
    meta:
        author = "Example Team"
        date = "2026-02-11"
        reference = "https://example.test/r/53"
        mitre_attack = "T1055, T1547.001"
    strings:
        $s0 = "cmd.exe /c"
        $r1 = /pass(word)?=/is
        $r2 = /pass(word)?=/i
        $r3 = /pass(word)?=/i
    condition:
        $s0 and $r1 and $r2 and $r3
}
