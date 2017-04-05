# BrowserGather
Fileless Extraction of Sensitive Browser Information with PowerShell

This project will include various cmdlets for extracting credential, history, and cookie/session data from the top 3 most popular web browsers (Chrome, Firefox, and IE). The goal is to perform this extraction entirely in-memory, without touching the disk of the victim. Currently Chrome credential and cookie extraction is supported. For more information, visit my blog at [sekirkity.com](http://sekirkity.com/).

## Instructions

First, import the module:

`import-module .\BrowserGather.ps1`

Next, use the cmdlet for the extraction you wish to perform. The following functions are supported:

### Get-ChromeCreds

Extracts credentials from the SQLite database. An optional path can specified. For example, the SQLite database may be stored in a profile folder like "Profile 1" rather than "Default".

`Get-ChromeCreds "C:\Users\sekirkity\AppData\Local\Google\Chrome\User Data\Profile 1\Login Data"`

It is highly recommend to pipe the object that is returned to the "format-list" cmdlet:

`Get-ChromeCreds | format-list *`

### Get-ChromeCookies

Extracts cookie information from the SQLite database. An optional path can specified.

`Get-ChromeCookies "C:\Users\sekirkity\AppData\Local\Google\Chrome\User Data\Profile 1\Cookies"`

It is highly recommend to pipe the object that is returned to the "format-list" cmdlet:

`Get-ChromeCookies | format-list *`

## Known Issues

* This script must be run under the context of the same user whose Chrome information you are trying to extract. This is due to the decryption of encrypted blobs from the Data Protection API. This is espescially important to remember when you have elevated your privileges to SYSTEM on a victim machine. There may be some ways around this, but are outside the scope of this project. 
* There is a chance of regex misses, espescially for Chrome cookie extraction. If this happens, the information extracted may appear out of order, or not at all. There are built-in checks to try and determine when this happens; keep an eye out for error messages. If you think you have encountered a regex miss, please send me the SQLite database file so I can fix it (if possible).
* For Chrome cookie extraction, once the SQLite database reaches a certain number of cookies (around 400), a small number of encrypted blobs will be stored non-contiguously. This makes it impossible to extract them via regex. This means around 1% of cookie extraction will fail and have have their blob replaced with an error message. 99% of the time this shouldn't be an issue.
* Some data that is extracted will need to be manually sorted. For example, with Chrome cookie extraction, the cookie information is presented as Hostname + Name + Path. Sadly, there is no easy way to separate this information with regex, but should be faily trivial to do by hand. 

## Roadmap

At some point I will look to incorporate Firefox/IE, taking a break for now.

## Acknowledgements

* [wald0](https://wald0.com/), [tifkin_](https://twitter.com/tifkin_), and [harmj0y](https://twitter.com/harmj0y) for requesting this project.
* [mattifestation](https://twitter.com/mattifestation) for his work on PowerShell, specifically the article on how to Regex a byte stream located [here](https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/24/use-powershell-and-regular-expressions-to-search-binary-data/).
* et0x for his existing work on PowerShell-based Chrome credential extraction, located [here](https://github.com/et0x/Get-ChromePasswords).
* [xorrior](https://twitter.com/xorrior) for his previous work in Empire and providing guidance.
* Coalfire/Veris Group, for allowing me to develop this project.
