Function removeDuplicatedUsers {
    <#
    .SYNOPSIS
    	Remove duplicated member of quota groups

    .PARAMETER gBaseName
        Mandatory. Initial name of Quota Groups

    .PARAMETER gBaseOU
        Mandatory. Where to search for Quota Groups
    
    .INPUTS
    	Parameters above

    .DESCRIPTION
    	Search quota groups and remove duplicated users, leaving users in major quota group size
    
    .OUTPUTS
    	Boolean

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	12/03/2014
    	Purpose/Change:	Created function
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$gBaseName, [Parameter(Mandatory=$true)][string]$gBaseOU)

    Process {
        Try {
            $gValues = @() # Create empty array
            $groups = Get-QADGroup -Name $gBaseName* -SearchRoot $gBaseOU -SizeLimit 0 | Select-Object Name -ErrorAction Stop
            foreach ( $group in $groups ) {
                $obj = New-Object PSObject
                $obj | Add-Member -type NoteProperty -name Name -value $group.Name
                $obj | Add-Member -type NoteProperty -name Quota -value ($group.Name.Split("_")[3] / 1MB)
                $gValues += $obj
            }
            $gValues = $gValues | Sort-Object Quota -descending
            for ( $x=0; $x -lt $gValues.Count-1; $x++ ) {
                for ( $y=$x; $y -lt $gValues.Count-1; $y++ ) {
                    Get-QADGroupMember $gValues[$x].Name | Remove-QADGroupMember $gValues[$y+1].Name | Out-Null
                }
            }
        }
        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Search for duplicated quota group members and removed it " + $aMessage
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "REMOVEDUPLICATED" -pVar1 $eTime -pVar2 $aMessage
            replaceFileString -Pattern '{REMOVEDUPLICATED}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function ignoredUsers {
    <#
    .SYNOPSIS
    	Load file of Ignored Users

    .DESCRIPTION
    	Load text file, one per line, of ignored users to not be added to array and processing
    
    .PARAMETER iFile
        Mandatory. Full path of the file
    
    .INPUTS
    	Parameters above

    .OUTPUTS
    	Content of File

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	25/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	ignoredUsers -iFile "C:\Temp\iFile.txt"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$iFile)

    Process {
        Try {
            $aMessage = $iFile
    	    $ignoredUsers = Get-Content $iFile -ErrorAction Stop
	        return $ignoredUsers
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Getting List of Ignored Users from File : " + $aMessage
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "IGNOREDUSERS" -pVar1 $eTime -pVar2 $aMessage
            replaceFileString -Pattern '{IGNOREDUSERS}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function getOlderLogons {
    <#
    .SYNOPSIS
    	Search in Directory for users with more than $lastLogonDays since lastlogon

    .DESCRIPTION
    	Search in AD for enabled users but with last logon more than $lastlogon config variable
    
    .PARAMETER lLogonDays
        Mandatory. Config variable for last logon search variable

    .PARAMETER bOU
        Mandatory. Config variable for SearchRoot attribute
    
    .INPUTS
    	Parameters above

    .OUTPUTS
    	Array of result with SamAccountName attribute

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	24/02/2014
    	Purpose/Change:	Added debug mode support

        Version: 		1.1
    	Author: 		Andreas Hansen
    	Creation Date:	24/02/2014
    	Purpose/Change:	Better error treatment
	
    .EXAMPLE
    	getOlderLogons -lLogonDays 60 -bOU "redmond.eu/Users"
    #>
    
    [CmdletBinding()]

    Param ([Parameter(Mandatory=$true)][int]$lLogonDays, [Parameter(Mandatory=$true)][string]$bOU)

    Process {
        Try {
            $cDate = GET-DATE
	        $deadline = ($cDate).AddDays(-($lLogonDays)).ToFileTimeUtc()
	        $ldapQuery = '(|(!(lastLogonTimeStamp=*))(lastLogonTimeStamp<=' + $deadline + '))'
            $aMessage = $lLogonDays
	        $older = Get-QADUser -Enabled -SearchRoot $bOU -SizeLimit 0 -LdapFilter $ldapQuery -IncludedProperties samAccountName | Select samAccountName -ErrorAction Stop
	        return $older
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Created list of Users with LastLogon Attribute greater than : " + $aMessage + " days"
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "GETOLDERLOGONS" -pVar1 $eTime -pVar2 $aMessage
            replaceFileString -Pattern '{GETOLDERLOGONS}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function getValidUsers {
    <#
    .SYNOPSIS
    	Search AD Valid Users

    .DESCRIPTION
    	Search for enabled users without size limit and include basic properties
    
    .PARAMETER gBaseName
        Mandatory. Initial name of Quota Groups

    .PARAMETER gBaseOU
        Mandatory. Where to search for Quota Groups
    
    .INPUTS
    	Parameters above

    .OUTPUTS
    	Array of result with SamAccountName (folder) attribute and Quota (quota group)

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	24/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	getValidUsers -gBaseName "GG_QUOTA_" -gBaseOU "redmond.us/Groups"
    #>
    
    [CmdletBinding()]

    Param ([Parameter(Mandatory=$true)][string]$gBaseName, [Parameter(Mandatory=$true)][string]$gBaseOU)

    Process {
        Try {
            $validUsers = @()
            $groups = Get-QADGroup -Name $gBaseName* -SearchRoot $gBaseOU -SizeLimit 0 | Select-Object Name -ErrorAction Stop
            foreach ($group in $groups) {
                $uGroups = @(Get-QADGroupMember -Identity $group.Name -Enabled:$true -IncludedProperties samAccountName -Indirect -SizeLimit 0 | Select samAccountName -ErrorAction Stop)
                foreach ( $uGroup in $uGroups ) {
                    $validUsers += @{Folder = $uGroup.samAccountName; Quota = $group.Name}
                }
            }
            $aMessage = $gBaseOU
	        return $validUsers
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Created list of Valid (ENABLED) Users in Groups Starting with : " + $aMessage
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "GETVALIDUSERS" -pVar1 $eTime -pVar2 $aMessage
            replaceFileString -Pattern '{GETVALIDUSERS}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function getDirList {
    <#
    .SYNOPSIS
    	List Directories

    .DESCRIPTION
    	Get list of Directories existent in Users Folder Base
    
    .PARAMETER bDir
        Mandatory. Path of Users Base Folder
    
    .INPUTS
    	Parameters above

    .OUTPUTS
    	Array of Directories

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	24/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	getDirList -bDir "c:\temp"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$bDir)

    Process {
        Try {
	        $dirList = Get-ChildItem -Path $bDir -ErrorAction Stop
            $aMessage = $bDir
	        return $dirList
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Created list of Already Existent Personal Folders in Path : " + $aMessage
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "GETDIRLIST" -pVar1 $eTime -pVar2 $aMessage
            replaceFileString -Pattern '{GETDIRLIST}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function filterUsers {
    <#
    .SYNOPSIS
    	Filter Users in Arrays

    .DESCRIPTION
    	Filter based on restrictions, the users will be verified through folders
    
    .PARAMETER vUsers
        Mandatory. Array of valid Users
    
    .PARAMETER oLogons
        Mandatory. Array of old users

    .PARAMETER ignoredUsersPre
        Mandatory. Array from Config containing initials that are ignored. Ex: svc

    .PARAMETER iUsers
        Mandatory. Array of ignored users, based on text file

    .INPUTS
    	Parameters above

    .OUTPUTS
    	Array of Filtered Users

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	26/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	filterUsers -vUsers $array -oLogons $array -ignoredUsersPre $string -iUsers $array
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][array]$vUsers,[Parameter(Mandatory=$true)][array]$oLogons, `
            [Parameter(Mandatory=$true)][array]$ignoredUsersPre,[Parameter(Mandatory=$true)][array]$iUsers)
	
    Process {
        Try {
	        # Loop through valid users list
	        $rUsers = @()
	        foreach ( $user in $vUsers ) {
		        if ( $user.Folder.Length -ge 3 ) {
			        $userPre = $user.Folder.Substring(0,3)
			        if ( $ignoredUsersPre -notcontains $userPre ) {
				        # Check if this user is in older list	
				        $oLogon = cArray -aToSearch $oLogons -aToFind $user.Folder -aTribute "SamAccountName" -ErrorAction Stop
				        if ( $oLogon -ne "true" ) {
					        # Check if this user is in ignored list
					        $iUser = cArray -aToSearch $iUsers -aToFind $user.Folder -aTribute "SamAccountName" -ErrorAction Stop
					        if ( $iUser -ne "true" ) {
						        $rUsers += @{Folder = $user.Folder; Quota = $user.Quota}
					        }
				        }
			        }
		        }
	        }
	        # Return Result
	        return $rUsers
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Created list of Filtered Users"
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "FILTERUSERS" -pVar1 $eTime
            replaceFileString -Pattern '{FILTERUSERS}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function dirActions {
    <#
    .SYNOPSIS
    	Add Action correspondent to each folder

    .DESCRIPTION
    	Create associative array of dirs and correspondent actions
    
    .PARAMETER fPath
        Mandatory. String from config file, containing base path of users folder
    
    .PARAMETER dList
        Mandatory. Array of already existent folders, but can be null

    .PARAMETER rUsers
        Mandatory. Array of filtered Users

    .INPUTS
    	Parameters above

    .OUTPUTS
    	Array of Folders, Quotas and correspondent Actions

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	26/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	dirActions -fPath "C:\temp" -dList $array -rUsers $array
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$fPath,[Parameter(Mandatory=$false)][array]$dList,[Parameter(Mandatory=$true)][array]$rUsers)

    Process {
        Try {
	        $rDirs = @()
	        foreach ( $dir in $dList ) { # Loop through list of existent directories and put it in associative array - array of hashtables
                if ( $dir.Name -ne $appSettings["archivingDir"] ) {
		            $rDirs += @{Folder = $dir.Name; Quota = "-"; Action = "REMOVE"}
                }
	        }
            for ( $i=0; $i -lt $rUsers.Count; $i++ ) {
                $fCount = 0
                for ( $x=0; $x -lt $rUsers.Count; $x++ ) {
                    if ( $rUsers[$x].Folder -eq $rUsers[$i].Folder ) {
                        $fCount++
                    }
                }
		        $status = "OFF"
		        for ( $x=0; $x -lt $rDirs.Count; $x++ ) { # If folder name already exists in array
                    if ( $rUsers[$i].Folder -eq $rDirs[$x].Folder ) {
                        ## If dup, set it
                        if ( $fCount -ge 2 ) {
                            $rDirs[$x].Action = "DUPLICATE"
                            $rDirs[$x].Quota = "-"
                        } else {
                            $rDirs[$x].Quota = $rUsers[$i].Quota
                            $name = $fPath + "\" + $rDirs[$x].Folder
                            $rQuota = qAction $name null "GET" # Validate difference between actual quota and quota defined by group membership
                            if ( $rQuota -ne $rUsers[$i].Quota -or $rDirs[$x].Quota -eq "" ) {
                                $rDirs[$x].Action = "CHANGE-QUOTA" # Action to change quota
				            } else {
				                $rDirs[$x].Action = "NONE" # Does nothing
                            }
                        }
                        $status = "ON"
                    }
                }
		        if ( $status -eq "OFF" ) { # If dont find folder and $status = ON, add to array with CREATE action
			        $rDirs += @{Folder = $rUsers[$i].Folder; Quota = $rUsers[$i].Quota; Action = "CREATE"}
		        }
            }
	        # Return Result
	        return $rDirs
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            ## Log Creation
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Created Table with Folder Actions"
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            ## Create Table with Folder Actions to Log
            Log-Write -LogPath $sLogFile -LineValue " "
            Log-Write -LogPath $sLogFile -LineValue "------------------------------------------"
            for ( $x=0; $x -lt $rDirs.Count; $x++ ){
                $rQuota = convertTemplateToMB -qName $rDirs[$x].Quota
                $logMessage = "User/Folder: " + $rDirs[$x].Folder + "   |   Quota: " + $rQuota + "   |   Action: " + $rDirs[$x].Action
                Log-Write -LogPath $sLogFile -LineValue $logMessage
            }
            Log-Write -LogPath $sLogFile -LineValue "------------------------------------------"
            Log-Write -LogPath $sLogFile -LineValue " "

            ## Change info in mailTemplate
            $htmlMessage = getHtmlMessage -pSource "DIRACTIONS" -pVar1 $eTime
            replaceFileString -Pattern '{DIRACTIONS}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite
        }
    }
}

Function qAction {
    <#
    .SYNOPSIS
    	Quota Functions

    .DESCRIPTION
    	Quota related functions to apply in folders
    
    .PARAMETER qPath
        Mandatory. String containing path of users folder
    
    .PARAMETER qValue
        Optional. String with optional value

    .PARAMETER qAction
        Mandatory. String with action to do

    .INPUTS
    	Parameters above

    .OUTPUTS
    	Boolean

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	26/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
    	qAction -qPath "c:\temp" -qAction "GET"
        qAction -qPath "c:\temp" -qValue "GG_QUOTA_XXMB" -qAction "CHANGE"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$qPath,[Parameter(Mandatory=$false)][string]$qValue,[Parameter(Mandatory=$true)][string]$qAction)

    Process {
        Try {
            switch ( $qAction ) {
                "GET" {
                    $qCommand = dirquota q l /Path:$qPath
                    if ( $qCommand -match "Enabled" ) {
                        $qReturn = ($qCommand -match "Source Template").Split(":")[1].TrimStart(" ").Split(" ")[0]
                    }
                }
                "CHANGE" {
                    $qCommand = dirquota q m /Path:$qPath /sourcetemplate:$qValue
                    if ( $qCommand -match "successfully" ) {
                        $qReturn = "True"
                    }
                }
                "CREATE" {
                    $qCommand = dirquota q a /Path:$qPath /sourcetemplate:$qValue
                    If ( $qCommand -match "successfully" ) {
                        $qReturn = "True"
                    }
                }
            }
            return $qReturn
        }

        Catch {
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }
}

Function fActions {
    <#
    .SYNOPSIS
    	Folder Actions

    .DESCRIPTION
    	Folder related functions
    
    .PARAMETER fPath
        Mandatory. String containing path of users base folder
    
    .PARAMETER fName
        Mandatory. String containing name of the folder

    .PARAMETER fQuota
        Mandatory. String with quota / group value

    .PARAMETER fAction
        Mandatory. String with Action

    .INPUTS
    	Parameters above

    .OUTPUTS
    	None

    .NOTES
		Version: 		1.0
    	Author: 		Andreas Hansen
    	Creation Date:	25/02/2014
    	Purpose/Change:	Added debug mode support
	
    .EXAMPLE
        fActions -fPath "C:\temp" -fName "test" -fQuota "GG_QUOTA_XXMB" -fAction "REMOVE"
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$fPath,[Parameter(Mandatory=$true)][string]$fName, `
            [Parameter(Mandatory=$true)][string]$fQuota,[Parameter(Mandatory=$true)][string]$fAction)

    Process {
        Try {	
	        switch ( $fAction ) {
                "CREATE-QUOTA" {
                    ## Send Create Quota Command to qAction Switch
                    $qPath = $fPath + "\" + $fName
                    $rQuota = convertTemplateToMB($fQuota)
                    $qResult = qAction -qPath $qPath -qValue $fQuota -qAction "CREATE" -ErrorAction Stop
                    $aMessage = "Defined Quota of Folder " + $fName + " to " + $rQuota
                }
                "CHANGE-QUOTA" {
                    ## Send Modify Quota Command to qAction Switch
                    $qPath = $fPath + "\" + $fName
                    $rQuota = convertTemplateToMB($fQuota)
                    $qActualSize = convertTemplateToMB(qAction -qPath $qPath -qValue $fQuota -qAction "GET")
                    $qResult = qAction -qPath $qPath -qValue $fQuota -qAction "CHANGE"  -ErrorAction Stop
                    $aMessage = "Changed Quota of Folder " + $fName + " from " + $qActualSize + " to " + $rQuota
                }
		        "CREATE-FOLDER" {
			        New-Item -Path $fPath -Name $fName -ItemType directory | Out-Null -ErrorAction Stop
                    $aMessage = "Created folder " + $fName
		        }
		        "ARCHIVE-FOLDER" {
                    # Create Date Var
                    $eTime = Get-Date -UFormat "%d%m%Y" # Ex: 10032014
			        $src = $fPath + "\" + $fName
                    $dst = $fPath + "\" + $appSettings["archivingDir"] + "\" + $fName + "_" + $eTime
                    $fExist = Test-Path $dst
                    if ( $fExist -eq $True ) {
                        $aMessage = "Archived folder ( " + $fName + "_" + $eTime + " ) already exists! Will be archived on next schedule, probably..."
                    } else {
			            Move-Item -Path $src $dst -Force | Out-Null -ErrorAction Stop
                        $aMessage = "Moved folder to Archiving Dir and Renamed for Retention control - " + $fName + "_" + $eTime
                    }
		        }
                "REMOVE-FOLDER" {
                    Remove-Item ($fPath + "\" + $fName) -Force -Recurse | Out-Null -ErrorAction SilentlyContinue
                    $aMessage = "Removed folder <b>" + $fName.Split("_")[0] + "</b> from user <b>" + $fQuota + "</b><br /> `
                            archived <span style='font-color: green; font-weight: bold;'>" + ($fName.Split("_")[1]).Substring(0,2) + "/" `
                            + ($fName.Split("_")[1]).Substring(2,2) + "/" + ($fName.Split("_")[1]).Substring(4,4) + "</span>"
                }
		        "REMOVE-SHARE" {
			        $name = $fname + "$"
                    if ( Get-WmiObject -Class Win32_Share -ComputerName . -Filter "Name='$name'" ) {
			            (Get-WmiObject -Class Win32_Share -ComputerName . -Filter "Name='$name'").InvokeMethod("Delete",$null) | Out-Null -ErrorAction SilentlyContinue
                    }
                    $aMessage = "Removed Share of Folder " + $fName
		        }
		        "CREATE-SHARE" {
		            $name = $fName + "$"
		            $path = $fPath + "\" + $fName
		            $description = $fName

		            $Method = "Create"
		            $sd = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance()

		            ## Permission Share - svc user
		            $ACE = ([WMIClass] "Win32_ACE").CreateInstance()
		            $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()
		            $Trustee.Name = $appSettings["runas"]
		            $Trustee.Domain = $appSettings["domain"]
		            $ace.AccessMask = 2032127
		            $ace.AceFlags = 3
		            $ace.AceType = 0
		            $ACE.Trustee = $Trustee 
		            $sd.DACL += $ACE.psObject.baseobject

		            ## Permission Share - the user
		            $ACE = ([WMIClass] "Win32_ACE").CreateInstance()
		            $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()
		            $Trustee.Name = $fName
		            $Trustee.Domain = $appSettings["domain"]
		            $ace.AccessMask = 1245631 
		            $ace.AceFlags = 3 # Should almost always be three. Really. don't change it.
		            $ace.AceType = 0 # 0 = allow, 1 = deny
		            $ACE.Trustee = $Trustee 
		            $sd.DACL += $ACE.psObject.baseobject

		            ## Permission Share - Domain Admins
		            $ACE = ([WMIClass] "Win32_ACE").CreateInstance()
		            $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()
		            $Trustee.Name = "Domain Admins"
		            $Trustee.Domain = $appSettings["domain"]
		            $ace.AccessMask = 2032127
		            $ace.AceFlags = 3
		            $ace.AceType = 0
		            $ACE.Trustee = $Trustee 
		            $sd.DACL += $ACE.psObject.baseobject

		            $mc = [WmiClass]"Win32_Share"
		            $InParams = $mc.psbase.GetMethodParameters($Method)
		            $InParams.Access = $sd
		            $InParams.Description = $description
		            $InParams.MaximumAllowed = $Null
		            $InParams.Name = $name
		            $InParams.Password = $Null
		            $InParams.Path = $path
		            $InParams.Type = [uint32]0

                    $aMessage = "Created Share of folder " + $fName
		            $mc.PSBase.InvokeMethod($Method, $InParams, $Null) | Out-Null -ErrorAction Stop
		        }
		        "CREATE-ACL" {
			        $folderPath = $fPath + "\" + $fName # Folder Path with name

    		        ## Take ownership with PSCX
			        Set-Privilege (new-object Pscx.Interop.TokenPrivilege "SeRestorePrivilege", $true) #Necessary to set Owner Permissions
			        Set-Privilege (new-object Pscx.Interop.TokenPrivilege "SeBackupPrivilege", $true) #Necessary to bypass Traverse Checking
			        Set-Privilege (new-object Pscx.Interop.TokenPrivilege "SeTakeOwnershipPrivilege", $true) #Necessary to override FilePermissions & take Ownership

			        $acl = Get-Acl $folderPath # Get Actual ACL on Folder
			        $acl.SetAccessRuleProtection($true,$true)
                    # Remove Inheritance
			        Set-Acl $folderPath $acl

			        $acl = Get-Acl $folderPath # Get Actual ACL on Folder
			        $acl.Access | %{$acl.RemoveAccessRule($_)} | Out-Null
                    # Remove ACL
			        Set-Acl $folderPath $acl

			        $blankdirAcl = New-Object System.Security.AccessControl.DirectorySecurity
			        $blankdirAcl.SetOwner([System.Security.Principal.NTAccount]$appSettings["dirOwner"])
			        (Get-Item $folderPath).SetAccessControl($blankdirAcl)

			        ## Define Permission Flags
			        $InheritanceFlag = "ContainerInherit,ObjectInherit"
        	        $PropagationFlag = "None"
			        $objType = "Allow"
			
			        ## Define Permission of Folder to Local Administrators
			        $objUser = $appSettings["runas"]
			        $colRights = [System.Security.AccessControl.FileSystemRights] “FullControl”
			        $Args = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
			        $ACL = Get-Acl $folderPath
			        $ACL.SetAccessRule($Args)
			        Set-Acl $folderPath $ACL | Out-Null -ErrorAction Stop

			        ## Define Permission of Folder to Domain Admins
			        $objUser = "Domain Admins"
			        $colRights = [System.Security.AccessControl.FileSystemRights] “FullControl”
			        $Args = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
			        $ACL = Get-Acl $folderPath
			        $ACL.SetAccessRule($Args)
			        Set-Acl $folderPath $ACL | Out-Null -ErrorAction Stop

			        ## Define Permission of Folder Owner to Username
			        $objUser = $fName
			        $colRights = [System.Security.AccessControl.FileSystemRights] “Modify”
			        $Args = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
			        $ACL = Get-Acl $folderPath
			        $ACL.SetAccessRule($Args)
			        Set-Acl $folderPath $ACL | Out-Null -ErrorAction Stop

                    $aMessage = "Defined ACL of folder " + $fName
		        }
		        "SET-HOMEDIRECTORY" {
                    $homeDir = "\\" + $appSettings["fileserver"] + "\" + $fName + "$"
			        Set-QADUser -Identity $fName -HomeDrive $appSettings["homeDrive"] -HomeDirectory $homeDir | Out-Null
                    $aMessage = "Defined AD HomeDirectory Attribute to: " + $homeDir
		        }
                "REMOVE-HOMEDIRECTORY" {
			        Set-QADUser -Identity $fName -HomeDirectory "" | Out-Null
                    $aMessage = "Redefined AD HomeDirectory Attribute to LocalPath"
                }
	        }
        }

        Catch {
            write-host $fAction
            errorPostprocess $MyInvocation.MyCommand $($_.Exception.Message)
        }
    }

    End {
        if ($?) {
            $eTime = get-date -uformat "%H:%M:%S"
            $logMessage = $eTime + " - Completed Folder Action: " + $aMessage
            Log-Write -LogPath $sLogFile -LineValue $logMessage

            # Return Message
            $rMsg = @($etime, $aMessage)
            return $rMsg
        }
    }
}