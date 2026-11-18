# Reports

Every report reads the text of the active editor and opens its result as a new Markdown document. Your file is never changed and nothing is sent anywhere. The examples below come from the sample file (Open Sample File).

## Show Rule Summary

Command: **Detection Rule Atlas: Show Rule Summary**

For a YARA file: the imports and every rule with its modifiers (private, global), tags, number of strings and meta fields. For a Sigma file: every rule (documents separated by ---) with its title, status, level and log source (category, product, service).

Example (sample file):

> # Rule Summary
>
> YARA file with 2 rules.
>
> Imports: pe.
>
> | Line | Rule | Modifiers | Tags | Strings | Meta fields |
> | ---: | --- | --- | --- | ---: | ---: |
> | 4 | Lab\_Loader\_Injection | - | windows loader | 5 | 4 |
> | 21 | Lab\_Webshell | - | webshell T1505\_003 | 2 | 2 |

## Show Syntax Check

Command: **Detection Rule Atlas: Show Syntax Check**

YARA: rules defined twice, rules not closed or without a condition, strings defined twice, empty strings, malformed hex strings, and conditions that use strings which are not defined (also $x* patterns). Sigma: missing title, logsource or detection, a detection without condition, conditions that use unknown search identifiers, status and level values outside the Sigma lists, and ids used twice.

Example (sample file):

> # Syntax Check
>
> 1 problem found.
>
> | Line | Problem |
> | ---: | --- |
> | 21 | condition of rule Lab\_Webshell uses \$p3, which is not defined |

## Show Metadata Check

Command: **Detection Rule Atlas: Show Metadata Check**

YARA: rules without author, description, date or reference meta, and dates that are not YYYY-MM-DD. Sigma: rules without id, status, description, author, date, level, tags or falsepositives, ids that are not UUIDs, and dates that are not YYYY-MM-DD or YYYY/MM/DD.

Example (sample file):

> # Metadata Check
>
> 3 findings.
>
> | Line | Rule | Finding |
> | ---: | --- | --- |
> | 4 | Lab\_Loader\_Injection | missing meta: reference |
> | 21 | Lab\_Webshell | missing meta: description, reference |
> | 25 | Lab\_Webshell | date 11/02/2026 is not YYYY-MM-DD |

## Show Quality Review (Pro)

Command: **Detection Rule Atlas: Show Quality Review** (Pro; part of the 14-day trial)

YARA: strings the condition never uses, text and hex strings shorter than 4 bytes, regular expressions starting with .* or .+, and conditions that use none of the strings. Sigma: values that are only a wildcard, contains, startswith and endswith values shorter than 3 characters, high and critical rules without falsepositives, and deprecated rules.

Example (sample file):

> # Quality Review
>
> 4 findings.
>
> | Line | Rule | Check | Finding |
> | ---: | --- | --- | --- |
> | 14 | Lab\_Loader\_Injection | short_atom | hex string \$mz has fewer than 4 fixed bytes, which slows scanning and matches often |
> | 15 | Lab\_Loader\_Injection | slow_regex | regex \$cfg starts with .\* or .\+, which makes scanning slow |
> | 16 | Lab\_Loader\_Injection | unused_string | string \$old is never used in the condition |
> | 28 | Lab\_Webshell | unused_string | string \$p2 is never used in the condition |

## Show ATT&CK Coverage (Pro)

Command: **Detection Rule Atlas: Show ATT&CK Coverage** (Pro; part of the 14-day trial)

Collects ATT&CK technique ids (such as T1059.001) and tactics (such as execution) from Sigma tags and from YARA tags and meta values, counts the rules per technique and per tactic, and lists the rules that carry no ATT&CK tag at all.

Example (sample file):

> # ATT&CK Coverage
>
> 2 rules, 3 techniques, 0 tactics.
>
> ## Techniques
>
> | Technique | Rules |
> | --- | ---: |
> | T1027 | 1 |
> | T1055 | 1 |
> | T1505.003 | 1 |
>
> ## Tactics
>
> No tactic tags.
>
> ## Rules without ATT&CK tags
>
> Every rule has an ATT&CK tag.
