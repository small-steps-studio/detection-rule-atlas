# Troubleshooting

## The report says the file is not valid

A file is read as Sigma when it has a line starting with detection: (and title: or detection:), and as YARA when a line starts with rule <name> (after optional private or global). Other files are reported as containing no YARA or Sigma rules. Sigma files are read line by line without a YAML library: the usual layout of SigmaHQ rules is supported.

## The file is too large

Reports read files up to the size set in `detectionRuleAtlas.maxFileSizeMB` (50 MB by default and at most). VS Code passes files only up to 50 MB to extensions, so a larger file cannot be read by any extension: split it, or save a shorter one.

## The preview does not open

The report always opens as a Markdown document. If the preview stays closed, set `detectionRuleAtlas.openReportsAsPreview` to true and check that the built-in Markdown extension is enabled.

## Pro or the trial does not unlock

Run **Detection Rule Atlas: Show Licence Status**. It tells whether a key is stored, whether it was checked, and how many trial days are left. Details are in [licence.md](licence.md).

## Something else

Run **Detection Rule Atlas: Report A Problem**. It copies a diagnostics block (versions, settings, licence state; no file contents) and opens the issues page.
