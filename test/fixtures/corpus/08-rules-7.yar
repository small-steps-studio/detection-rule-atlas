import "pe"
import "math"

// invented rules
rule Loader_70 : linux
{
    meta:
        author = "Example Team"
        description = "Invented rule 70"
        date = "2025/12/01"
    strings:
        $r0 = /pass(word)?=/is
        $h1 = { 46 1A 11 92 DE 5A }
    condition:
        uint16(0) == 0x5A4D and $r0
}
