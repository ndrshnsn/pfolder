Function replaceFileString {
    <#
    .SYNOPSIS
    Replaces strings in files using a regular expression.

    .DESCRIPTION
    Replaces strings in files using a regular expression. Supports
    multi-line searching and replacing.

    .PARAMETER Pattern
    Specifies the regular expression pattern.

    .PARAMETER Replacement
    Specifies the regular expression replacement pattern.

    .PARAMETER Path
    Specifies the path to one or more files. Wildcards are permitted. Each
    file is read entirely into memory to support multi-line searching and
    replacing, so performance may be slow for large files.

    .PARAMETER LiteralPath
    Specifies the path to one or more files. The value of the this
    parameter is used exactly as it is typed. No characters are interpreted
    as wildcards. Each file is read entirely into memory to support
    multi-line searching and replacing, so performance may be slow for
    large files.

    .PARAMETER CaseSensitive
    Specifies case-sensitive matching. The default is to ignore case.

    .PARAMETER Multiline
    Changes the meaning of ^ and $ so they match at the beginning and end,
    respectively, of any line, and not just the beginning and end of the
    entire file. The default is that ^ and $, respectively, match the
    beginning and end of the entire file.

    .PARAMETER UnixText
    Causes $ to match only linefeed (\n) characters. By default, $ matches
    carriage return+linefeed (\r\n). (Windows-based text files usually use
    \r\n as line terminators, while Unix-based text files usually use only
    \n.)

    .PARAMETER Overwrite
    Overwrites a file by creating a temporary file containing all
    replacements and then replacing the original file with the temporary
    file. The default is to output but not overwrite.

    .PARAMETER Force
    Allows overwriting of read-only files. Note that this parameter cannot
    override security restrictions.

    .PARAMETER Encoding
    Specifies the encoding for the file when -Overwrite is used. Possible
    values are: ASCII, BigEndianUnicode, Unicode, UTF32, UTF7, or UTF8. The
    default value is ASCII.

    .INPUTS
    System.IO.FileInfo.

    .OUTPUTS
    System.String without the -Overwrite parameter, or nothing with the
    -Overwrite parameter.

    .LINK
    about_Regular_Expressions

    .EXAMPLE
    C:\>Replace-FileString.ps1 '(Ferb) and (Phineas)' '$2 and $1' Story.txt
    This command replaces the string 'Ferb and Phineas' with the string
    'Phineas and Ferb' in the file Story.txt and outputs the file. Note
    that the pattern and replacement strings are enclosed in single quotes
    to prevent variable expansion.

    .EXAMPLE
    C:\>Replace-FileString.ps1 'Perry' 'Agent P' Ferb.txt -Overwrite
    This command replaces the string 'Perry' with the string 'Agent P' in
    the file Ferb.txt and overwrites the file.
    #>

    [CmdletBinding(DefaultParameterSetName="Path",
                   SupportsShouldProcess=$TRUE)]
    param(
      [parameter(Mandatory=$TRUE,Position=0)]
        [String] $Pattern,
      [parameter(Mandatory=$TRUE,Position=1)]
        [String] [AllowEmptyString()] $Replacement,
      [parameter(Mandatory=$TRUE,ParameterSetName="Path",
        Position=2,ValueFromPipeline=$TRUE)]
        [String[]] $Path,
      [parameter(Mandatory=$TRUE,ParameterSetName="LiteralPath",
        Position=2)]
        [String[]] $LiteralPath,
        [Switch] $CaseSensitive,
        [Switch] $Multiline,
        [Switch] $UnixText,
        [Switch] $Overwrite,
        [Switch] $Force,
        [String] $Encoding="ASCII"
    )

    begin {
      # Throw an error if $Encoding is not valid.
      $encodings = @("ASCII","BigEndianUnicode","Unicode","UTF32","UTF7",
                     "UTF8")
      if ($encodings -notcontains $Encoding) {
        throw "Encoding must be one of the following: $encodings"
      }

      # Extended test-path: Check the parameter set name to see if we
      # should use -literalpath or not.
      function test-pathEx($path) {
        switch ($PSCmdlet.ParameterSetName) {
          "Path" {
            test-path $path
          }
          "LiteralPath" {
            test-path -literalpath $path
          }
        }
      }

      # Extended get-childitem: Check the parameter set name to see if we
      # should use -literalpath or not.
      function get-childitemEx($path) {
        switch ($PSCmdlet.ParameterSetName) {
          "Path" {
            get-childitem $path -force
          }
          "LiteralPath" {
            get-childitem -literalpath $path -force
          }
        }
      }

      # Outputs the full name of a temporary file in the specified path.
      function get-tempname($path) {
        do {
          $tempname = join-path $path ([IO.Path]::GetRandomFilename())
        }
        while (test-path $tempname)
        $tempname
      }

      # Use '\r$' instead of '$' unless -UnixText specified because
      # '$' alone matches '\n', not '\r\n'. Ignore '\$' (literal '$').
      if (-not $UnixText) {
        $Pattern = $Pattern -replace '(?<!\\)\$', '\r$'
      }

      # Build an array of Regex options and create the Regex object.
      $opts = @()
      if (-not $CaseSensitive) { $opts += "IgnoreCase" }
      if ($MultiLine) { $opts += "Multiline" }
      if ($opts.Length -eq 0) { $opts += "None" }
      $regex = new-object Text.RegularExpressions.Regex $Pattern, $opts
    }

    process {
      # The list of items to iterate depends on the parameter set name.
      switch ($PSCmdlet.ParameterSetName) {
        "Path" { $list = $Path }
        "LiteralPath" { $list = $LiteralPath }
      }

      # Iterate the items in the list of paths. If an item does not exist,
      # continue to the next item in the list.
      foreach ($item in $list) {
        if (-not (test-pathEx $item)) {
          write-error "Unable to find '$item'."
          continue
        }

        # Iterate each item in the path. If an item is not a file,
        # skip all remaining items.
        foreach ($file in get-childitemEx $item) {
          if ($file -isnot [IO.FileInfo]) {
            write-error "'$file' is not in the file system."
            break
          }

          # Get a temporary file name in the file's directory and create
          # it as a empty file. If set-content fails, continue to the next
          # file. Better to fail before than after reading the file for
          # performance reasons.
          if ($Overwrite) {
            $tempname = get-tempname $file.DirectoryName
            set-content $tempname $NULL -confirm:$FALSE
            if (-not $?) { continue }
            write-verbose "Created file '$tempname'."
          }

          # Read all the text from the file into a single string. We have
          # to do it this way to be able to search across line breaks.
          try {
            write-verbose "Reading '$file'."
            $text = [IO.File]::ReadAllText($file.FullName)
            write-verbose "Finished reading '$file'."
          }
          catch [Management.Automation.MethodInvocationException] {
            write-error $ERROR[0]
            continue
          }

          # If -Overwrite not specified, output the result of the Replace
          # method and continue to the next file.
          if (-not $Overwrite) {
            $regex.Replace($text, $Replacement)
            continue
          }

          # Do nothing further if we're in 'what if' mode.
          if ($WHATIFPREFERENCE) { continue }

          try {
            write-verbose "Writing '$tempname'."
            [IO.File]::WriteAllText("$tempname", $regex.Replace($text,
              $Replacement), [Text.Encoding]::$Encoding)
            write-verbose "Finished writing '$tempname'."
            write-verbose "Copying '$tempname' to '$file'."
            copy-item $tempname $file -force:$Force -erroraction Continue
            if ($?) {
              write-verbose "Finished copying '$tempname' to '$file'."
            }
            remove-item $tempname
            if ($?) {
              write-verbose "Removed file '$tempname'."
            }
          }
          catch [Management.Automation.MethodInvocationException] {
            write-error $ERROR[0]
          }
        } # foreach $file
      } # foreach $item
    } # process

    end { }
}

Function errorPostprocess {
    <#
    .SYNOPSIS
    	Do error treatment

    .DESCRIPTION
    	Put information in EventLog / Host / LogFile
    
    .PARAMETER functionName
        Mandatory. Name of the Function

    .PARAMETER exceptionMessage
        Mandatory. Type of Message

    .INPUTS
    	Parameters above

    .OUTPUTS
    	EventViewer / Host / LogFile

    .NOTES
		Version: 		1.1
    	Author: 		Andreas Hansen
    	Creation Date:	28/02/2014
    	Purpose/Change:	Write Error Messages
	
    .EXAMPLE
    	errorPostprocess "doSomething" "Cannot find file"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$functionName,[Parameter(Mandatory=$true)][string]$exceptionMessage)

    Process {
        ## Send to Host
        write-host "Caught an exception on Function: " -NoNewline -ForegroundColor Red
        write-host $functionName -ForegroundColor Green
        write-host "Exception Message: $exceptionMessage" -ForegroundColor Red

        ## Send to EventLog
        eventLog -eventSource $appSettings["evSource"] -eventType Error -eventID 10 -eventMessage `
            "Caught an exception on Function: $functionName | Exception Message: $exceptionMessage"

        ## Change info in mailTemplate
        $htmlMessage = getHtmlMessage -pSource "ERROR" -pVar1 $functionName -pVar2 $exceptionMessage
        replaceFileString -Pattern '{ERROR}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite

        ## Send to LogFile
        Log-Error -LogPath $sLogFile -ErrorDesc $exceptionMessage -ExitGracefully $True
    }
}

Function getHtmlMessage {
    <#
    .SYNOPSIS
    	Write messages to Event Viewer

    .DESCRIPTION
    	Get informatio and write it to Event Viewer
    
    .PARAMETER pSource
        Mandatory. Pattern to be substituted

    .PARAMETER pVar1
        Mandatory. Variable with pattern to substitute

    .PARAMETER pVar2
        Optional.

    .PARAMETER pVar3
        Optional.

    .INPUTS
    	Parameters above

    .OUTPUTS
    	HTML Correspondent Message

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	07/03/2014
    	Purpose/Change:	Convert messages to HTML
	
    .EXAMPLE
    	eventLog "myapp" Application 1 "test"
    #>
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$pSource, [Parameter(Mandatory=$true)]$pVar1, `
            [Parameter(Mandatory=$false)]$pVar2, [Parameter(Mandatory=$false)]$pVar3)

    Process {
        Try {
            switch ( $pSource ) {
                "ERROR" {
                    $htmlMessage = "<p class=MsoNormal style='font-size: 12px; color: black; font-weight: bold;'> `
                        Caught an exception on Function: <span style='color: red'>" + $pVar1 + "</p>"
                    $htmlMessage += "<p class=MsoNormal style='font-size: 12px; color: black; font-weight: bold;'> `
                        Exception Message: <span style='color: red'>" + $pVar2 + "</p>"
                }

                "REMOVEDUPLICATED" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 11px; color: black;'> `
                        Search and Remove Duplicated members of Quota Groups function Completed</td>"
                }

                "IGNOREDUSERS" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 11px; color: black;'> `
                        Getting List of Ignored Users from File <span style='font-size: 12px; color: #003300;'>`
                        " + $pVar2 + "</span></td>"
                }

                "GETOLDERLOGONS" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 11px; color: black;'> `
                        Created list of Users with LastLogon Attribute greater than `
                        <span style='font-size: 12px; color: #003300;'>" + $pVar2 + "</span> days</td>"
                }

                "GETVALIDUSERS" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 11px; color: black;'> `
                        Created list of Valid (ENABLED) Users in Groups at `
                        <span style='font-size: 12px; color: #003300;'>" + $pVar2 + "</span> directory folder</td>"
                }

                "GETDIRLIST" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 11px; color: black;;'> `
                        Created list of Already Existent Personal Folders in Path `
                        <span style='font-size: 12px; color: #003300;'>" + $pVar2 + "</span></td>"
                }

                "FILTERUSERS" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 10px; color: black;'> `
                        Created list of Filtered Users</td>"
                }

                "VERSION" {
                    $htmlMessage = "<span style='font-size: 16px; font-weight: bold;'>pFolder " + $pVar1 + " - Execution Log `
                        ( " + $pVar3 + " )</span></br >"
                    $htmlMessage += "<span style='font-size: 10px;'>For a complete actions/folder list, see log file: " + $pVar2 + "</span>"
                }

                "DIRACTIONS" {
                    $htmlMessage = "<td>" + $pVar1 + "</td><td style='font-size: 11px; color: black;'> `
                        Created Table with Folder Actions</td>"
                }

            }
            return $htmlMessage
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}

Function convertDateString {
    <#
    .SYNOPSIS
    	Convert string to DateTime object

    .DESCRIPTION
    	Convert string to DateTime using Posh internal functions
    
    .PARAMETER Date
        Mandatory. String to be converted

    .PARAMETER Format
        Mandatory. Format of string

    .INPUTS
    	Parameters above

    .OUTPUTS
    	DateTime object

    .NOTES
		Version: 		1.0
    	Author: 		Jakub Jares
    	Creation Date:	08/07/2013
    	Purpose/Change:	Convert string to DateTime
	
    .EXAMPLE
    	convertDateString -Date '12/10\2013 13:26-34' -Format 'dd/MM\\yyyy HH:mm-ss'
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$Date,[Parameter(Mandatory=$true)][string]$Format)

    Process {
        Try {
           $result = New-Object DateTime
 
           $convertible = [DateTime]::TryParseExact(
              $Date,
              $Format,
              [System.Globalization.CultureInfo]::InvariantCulture,
              [System.Globalization.DateTimeStyles]::None,
              [ref]$result)
 
           if ($convertible) { return $result }
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}

Function eventLog {
    <#
    .SYNOPSIS
    	Write messages to Event Viewer

    .DESCRIPTION
    	Get informatio and write it to Event Viewer
    
    .PARAMETER eventSource
        Mandatory. Source of log

    .PARAMETER eventType
        Mandatory. Type of Message

    .PARAMETER eventID
        Mandatory. Id of Message

    .PARAMETER eventMessage
        Mandatory. Message of EventLog

    .INPUTS
    	Parameters above

    .OUTPUTS
    	None

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	27/02/2014
    	Purpose/Change:	Write messages
	
    .EXAMPLE
    	eventLog "myapp" Application 1 "test"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$eventSource,[Parameter(Mandatory=$true)][string]$eventType, `
           [Parameter(Mandatory=$true)][int]$eventID, [Parameter(Mandatory=$true)][string]$eventMessage)

    Process {
        Try {
            Write-EventLog -LogName Application -Source $eventSource -EntryType $eventType -EventId $eventID `
                -Category 0 -Message $eventMessage -ErrorAction Stop
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}

Function convertTemplateToMB {
    <#
    .SYNOPSIS
    	Convert quota folder / group to MB

    .DESCRIPTION
    	Convert Quota Template naming to MB
    
    .PARAMETER qName
        Mandatory. String of quota information

    .INPUTS
    	Parameters above

    .OUTPUTS
    	String converted

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	25/02/2014
    	Purpose/Change:	Added debug mode support

		Version: 		1.1
    	Author: 		Andreas Hansen
    	Creation Date:	28/02/2014
    	Purpose/Change:	Changed split mode from 2 to 3 after added servername to quotagroup name.
	
    .EXAMPLE
    	convertTemplateToMB -qName "GG_QUOTA_100MB"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$qName)

    Process {
        Try {
            $tConverted = $qName.Split("_")[3]
            return $tConverted
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}

Function getModule {
    <#
    .SYNOPSIS
    	Get and Load Module

    .DESCRIPTION
    	Check por presence and lod module if needed
    
    .PARAMETER mName
        Mandatory. Name of the Module
    
    .INPUTS
    	Parameters above

    .OUTPUTS
    	Boolean

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	24/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	getModule -mName "Microsoft.PowerShell.Security"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$mName)

    Process {
        Try {
            $retVal = "True"
            if (!(Get-Module -Name $mName)) {
                $retVal = Get-Module -ListAvailable | where { $_.Name -eq $mName }
                if ($retVal) {
                    try {
                        Import-Module $mName -ErrorAction SilentlyContinue
                    }

                    catch {
                        $retVal = "False"
                    }
                }
            }
            return $retVal
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}

Function cArray {
    <#
    .SYNOPSIS
    	Compare Arrays, similar to -contains

    .DESCRIPTION
    	Compare values into diferent arrays - or - better than -contains
    
    .PARAMETER aToSearch
        Mandatory. Array to Search
    
    .PARAMETER aToFind
        Mandatory. Array to Find similar string

    .PARAMETER aTribute
        Mandatory. Attribute to find / compare

    .INPUTS
    	Parameters above

    .OUTPUTS
    	Boolean

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	24/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	cArray -aToSearch $array1 -aToFind $array2 -aTribute "example"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][array]$aToSearch,[Parameter(Mandatory=$true)][array]$aToFind,[Parameter(Mandatory=$true)][string]$aTribute)
    
    Process {
        Try {
	        foreach ( $item in $aToSearch ) {
		        if ( $item.$aTribute -eq $aToFind ) {
			        return "true"
		        }
	        }
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}
