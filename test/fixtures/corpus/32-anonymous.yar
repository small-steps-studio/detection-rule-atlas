rule Anon { strings: $ = "first" $ = "second" condition: for any of ($*) : ( # > 2 ) }
