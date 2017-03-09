# BrowserGather
Fileless Extraction of Sensitive Browser Information with PowerShell

This project will include various cmdlets for extracting credential, history, and cookie/session data from the top 3 most popular web browsers (Chrome, Firefox, and IE). The goal is to perform this extraction entirely in-memory, without touching the disk of the victim. Currently only Chrome credential extraction is supported, but more to come!

## Instructions

First, import the module:

`import-module .\BrowserGather.ps1`

Next, use the cmdlet for the extraction you wish to perform. For example:

`Get-ChromeCreds`

You can also include an optional path. For example, the SQLite database may be stored in a profile folder like "Profile 1" rather than "Default".

`Get-ChromeCreds "C:\Users\sekirkity\AppData\Local\Google\Chrome\User Data\Profile 1\Login Data"`

## Known Issues

This script must be run under the context of the same user whose Chrome information you are trying to extract. This is due to the decryption of password information from the Data Protection API. This is espescially important to remember when you have elevated your privileges to SYSTEM on a victim machine. There may be some ways around this, but are outside the scope of this project. 

## Roadmap

Chrome browser history and cookie/session data are up next. Afterwards I will look at incorporating other browsers, depending on need/feedback.

## Acknowledgements

* [wald0](https://wald0.com/), [tifkin_](https://twitter.com/tifkin_), and [harmj0y](https://twitter.com/harmj0y) for requesting this project.
* [mattifestation](https://twitter.com/mattifestation) for his work on PowerShell, specifically the article on how to Regex a byte stream located [here](https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/24/use-powershell-and-regular-expressions-to-search-binary-data/).
* et0x for his existing work on PowerShell-based Chrome credential extraction, located [here](https://github.com/et0x/Get-ChromePasswords).
* [xorrior](https://twitter.com/xorrior) for his previous work in Empire and providing guidance.
