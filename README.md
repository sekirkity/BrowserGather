# BrowserGather
Fileless Extraction of Sensitive Browser Information with PowerShell

This project will include various cmdlets for extracting credential, history, and cookie/session data from the top 3 most popular web browsers (Chrome, Firefox, and IE). The goal is to perform this extraction entirely in-memory, without touching the disk of the victim. Currently only Chrome credential extraction is supported, but more to come!

## Instructions

First, import the module:

`import-module BrowserGather.ps1`

Next, use the cmdlet for the extraction you wish to perform. For example:

`Get-ChromeCreds`

## Roadmap

Chrome browser history and cookie/session data are up next. Afterwards I will look at incorporating other browsers, depending on need/feedback.

## Acknowledgements

* [wald0](https://wald0.com/), [tifkin_](https://twitter.com/tifkin_), and [harmj0y](https://twitter.com/harmj0y) for requesting this project.
* [mattifestation](https://twitter.com/mattifestation) for his work on PowerShell, specifically the article on how to Regex a byte stream located [here](https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/24/use-powershell-and-regular-expressions-to-search-binary-data/).
* et0x for his existing work on PowerShell-based Chrome credential extraction, located [here](https://github.com/et0x/Get-ChromePasswords).
