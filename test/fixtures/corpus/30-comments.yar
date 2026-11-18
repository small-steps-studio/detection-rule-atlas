/* rule Fake { condition: true } */
// rule AlsoFake { }
rule Real { strings: $a = "rule Inside { }" condition: $a } // trailing
