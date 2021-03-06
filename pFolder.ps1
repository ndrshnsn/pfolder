<#
.SYNOPSIS
    Mail Application

.NOTES
    Version:        2.3
    Author:         Andreas Hansen
    Creation Date:  15/02/2014
    Purpose/Change: Load Config File, functions, libraries and Execute Application
#>

#-------------------------------[Initializations]------------------------------
## Load Config File
. .\lib\config.ps1 pFolder.xml

## Load Utils File
. .\lib\utils.ps1

## Load Logging File
. .\lib\logging

## Load Functions File
. .\lib\functions

## Initialize EventLog Source
if ( [System.Diagnostics.EventLog]::SourceExists($appSettings["evSource"]) -eq $false ) {
    New-EventLog –LogName Application –Source $appSettings["evSource"]
}

## Initialize Logging
$dYear = Get-Date -UFormat %Y
$dMonth = Get-Date -UFormat %m
$dDay = Get-Date -UFormat %d
$dHour = Get-Date -UFormat "%H%M%S"
$dName = $appSettings["homeFolder"] + "\" + $appSettings["logPath"] `
            + "\" + $dYear + "\" + $dMonth + "\" + $dDay

## Check if file exists and delete if it does
If(!(Test-Path -Path $dName)){
    New-Item -ItemType Directory -Path $dName | Out-Null
}
$sScriptVersion = $appSettings["version"]
$sLogPath = $dname
$sLogName = $appSettings["logFileName"] + "_" + $dHour + ".log"
$sLogFile = $sLogPath + "\" + $sLogName
Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
eventLog -eventSource $appSettings["evSource"] -eventType "Information" -eventID 0 -eventMessage `
            "Initializing Processing of pFolder"

## Initialize mailTemplate and mailTemplateTmp
$fileRandom = Get-Random
$mailTemplateTmp = $appSettings["homeFolder"] + "\tmp\" + $fileRandom + ".htm"
$mailTemplate = $appSettings["homeFolder"] + "\" + $appSettings["mailTemplate"]
Copy-Item $mailTemplate $mailTemplateTmp

## Change info in mailTemplate
$htmlMessage = getHtmlMessage -pSource "VERSION" -pVar1 $appSettings["version"] -pVar2 $sLogFile -pVar3 $appSettings["fileserver"]
replaceFileString -Pattern '{VERSION}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite

## Define ErrorActionPreference
$ErrorActionPreference = $appSettings["errorMode"]

## Check for Available MOdules and Load It
foreach ( $sModule in $appSettings["modules"] ) {
    $sModuleTest = getModule -mName $sModule | Out-Null -ErrorAction Stop
    if ( $sModuleTest -eq "False" ) {
        break
    }
}

## Add PSSnapin
add-PsSnapin $appSettings["snapin"] –erroraction SilentlyContinue 
if ((Get-PSSnapin $appSettings["snapin"]) –eq $NULL) {
    Write-Host "Error loading PSSnapin Quest Activeroles"
    $sModuleTest = "False"
    exit
}

## If loaded all Modules
if ( $sModuleTest -ne "False" ) {

    # search groups for duplicated members and remove it, sorted by quota size
    removeDuplicatedUsers $appSettings["groupBaseName"] -gBaseOU $appSettings["groupBaseOU"]

    # get list of ignored users - file based
    $iUsers = ignoredUsers -iFile $appSettings["ignoredUsersFile"]

    # get list of ignored users - ad lastlogon based
    $oLogons = getOlderLogons -lLogonDays $appSettings["lastLogonDays"] -bOU $appSettings["baseOU"]

    # get list of enabled users - ad enabled property based
    $vUsers = getValidUsers -gBaseName $appSettings["groupBaseName"] -gBaseOU $appSettings["groupBaseOU"]

    # get list of folders - dir list based
    $dList = getDirList -bDir $appSettings["baseDir"]

    # get list of real valid users to verify folders
    $rUsers = filterUsers -vUsers $vUsers -oLogons $oLogons -ignoredUsersPre $appSettings["ignoredUsersPre"] -iUsers $iUsers

    # get list of folder and actions
    $dActions =  dirActions $appSettings["baseDir"] $dList $rUsers

    # get list of archived folders
    $aDir = $appSettings["baseDir"] + "\" + $appSettings["archivingDir"]
    $aList = getDirList -bDir $aDir

    ## Switch between run options
    switch ( $appSettings["runMode"] ) {
        "RUN" {
            $htmlMessage = ""
            $sendEmail = "False"
            ## Do the Array Folder Actions
            for ( $x=0; $x -lt $dActions.Count; $x++ ){
                Log-Write -LogPath $sLogFile -LineValue "---------------------------------------------------------------------"
                if ( $dActions[$x].Action -eq "NONE" ) {
                    $eTime = get-date -uformat "%H:%M:%S"
                    $logMessage = $eTime + " - Initializing Processing Actions for User: " + $dActions[$x].Folder + " - NOTHING TO DO"
                    Log-Write -LogPath $sLogFile -LineValue $logMessage
                } else {
                    $sendEmail = "True"
                    $eTime = get-date -uformat "%H:%M:%S"
                    $username = get-qaduser -identity $dActions[$x].Folder | Select Name
                    $rQuota = convertTemplateToMB -qName $dActions[$x].Quota
                    $logMessage = $eTime + " - Initializing Processing Actions for User: " + $dActions[$x].Folder
                    Log-Write -LogPath $sLogFile -LineValue $logMessage

                    # Switch through Folder Action
                    switch ( $dActions[$x].Action ) {
                        "CREATE" {
                            $actionColor = "green"
                        }
                        "DUPLICATE" {
                            $actionColor = "blue"
                        }
                        "CHANGE-QUOTA" {
                            $actionColor = "#990033"
                        }
                        "REMOVE" {
                            $actionColor = "red"
                        }
                    }

                    # Create HTML Table with User Information
                    $htmlMessage += "<p class=MsoNormal><table id='hor-minimalist-b' style='width: 600px;'><thead><tr>"
        	        $htmlMessage += "<th scope='col' colspan='4'>Initializing Processing Actions for User: " + $dActions[$x].Folder + "</th>"
                    $htmlMessage += "</tr></thead><tbody>"
                    $htmlMessage += "<tr><td style='font-weight: bold; width: 80px;'>Username</td><td style='font-weight: normal; width: 330px;'>" + $dActions[$x].Folder + "</td> `
                                        <td style='font-weight: bold; width: 50px;'>Action</td><td style='font-weight: normal; width: 80px; color: " + $actionColor + "'>" + $dActions[$x].Action + "</td></tr>"
                    $htmlMessage += "<tr><td style='border-bottom: 2px solid; font-weight: bold;'>Display Name</td><td style='border-bottom: 2px solid; font-weight: normal; width: 330px;'>" + $username.Name + "</td> `
                                        <td style='border-bottom: 2px solid; font-weight: bold;'>Quota</td><td style='border-bottom: 2px solid; font-weight: normal;'>" + $rQuota + "</td></tr>"

    	            switch ( $dActions[$x].Action ) {
    		            "CREATE" { # Create User Folder
    			            if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "CREATE-FOLDER" ) {
                                $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                <td colspan='3'>" + $fAction[1] + "</tr>"
                                if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "CREATE-ACL" ) {
                                    $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                    <td colspan='3'>" + $fAction[1] + "</tr>"
                                    if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "CREATE-SHARE" ) {
                                        $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                        <td colspan='3'>" + $fAction[1] + "</tr>"
                                        if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder $dActions[$x].Quota "CREATE-QUOTA" ) {
                                            $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                            <td colspan='3'>" + $fAction[1] + "</tr>"
                                            if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "SET-HOMEDIRECTORY" ) {
                                                $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                                <td colspan='3'>" + $fAction[1] + "</tr>"
                                            }
                                        }
                                    }
                                }
                            }
    		            }
            		    "CHANGE-QUOTA" {
            			    if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder $dActions[$x].Quota "CHANGE-QUOTA" ) {
                                $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                <td colspan='3'>" + $fAction[1] + "</tr>"
                            }
            		    }
    		            "REMOVE" {
    				        if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "REMOVE-SHARE" ) {
                                $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                <td colspan='3'>" + $fAction[1] + "</tr>"
                                if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "REMOVE-HOMEDIRECTORY" ) {
                                    $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                    <td colspan='3'>" + $fAction[1] + "</tr>"
    				                if ( $fAction = fActions $appSettings["baseDir"] $dActions[$x].Folder null "ARCHIVE-FOLDER" ) {
                                        $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                                        <td colspan='3'>" + $fAction[1] + "</tr>"
                                    }
                                }
                            }
    		            }
    	            }
                    # Close Table
                    $htmlMessage += "</tbody></table></p><br />"
                }
            }
            ## Change info in mailTemplate
            replaceFileString -Pattern '{FACTIONS}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite

            # Text log
            Log-Write -LogPath $sLogFile -LineValue "---------------------------------------------------------------------"
            Log-Write -LogPath $sLogFile -LineValue "Archiving Operations"

            # Create HTML Table with User Information
            $actualDate = Get-Date -UFormat "%d/%m/%Y"
            $retentionDate = (Get-Date).AddDays(-$appSettings["retentionDays"])
            $htmlMessage = "<p class=MsoNormal><table id='hor-minimalist-b' style='width: 600px;'><thead><tr>"
        	$htmlMessage += "<th scope='col' colspan='4'>Archiving Operations</th>"
            $htmlMessage += "</tr></thead><tbody>"
            $htmlMessage += "<tr><td style='border-bottom: 2px solid; font-weight: bold; width: 80px;'>Date</td><td style='border-bottom: 2px solid; font-weight: normal; width: 140px;'>" + $actualDate + "</td> `
                                <td style='border-bottom: 2px solid; font-weight: bold; width: 140px;'>Retention (" + $appSettings["retentionDays"] + " days)</td><td style='border-bottom: 2px solid; font-weight: normal;'>" + $retentionDate.Day + "/" + $retentionDate.Month + "/" + $retentionDate.Year + "</td></tr>"

            # Do Folder Archiving Operations
            foreach ( $dir in $aList ) {
                $username = get-qaduser -identity ($dir.Name).Split("_")[0] | Select Name
                $fDate = convertDateString -Date ((Get-Item ($aDir + "\" + $dir.Name)).Name.Split("_")[1]) -Format "ddMMyyyy"
                $rDate = (Get-Date).AddDays(-$appSettings["retentionDays"])
                if ( $fDate -lt $rDate ) { # If folder date is older than actual date minus retentionDays, remove it
                    $sendEmail = "True" # Send email, even no folder actions, but to report archiving operation
    			    if ( $fAction = fActions $aDir $dir.Name $username.Name "REMOVE-FOLDER" ) {
                       $htmlMessage += "<tr><td style='font-weight: bold;'>" + $fAction[0] + "</td> `
                                       <td colspan='3'>" + $fAction[1] + "</tr>"
                    }
                }
            }

            # Close Table
            $htmlMessage += "</tbody></table></p><br />"

            ## Change info in mailTemplate
            replaceFileString -Pattern '{ARCHIVE}' -Replacement $htmlMessage -Path $mailTemplateTmp -Overwrite

            ## Finalize Things
            eventLog -eventSource $appSettings["evSource"] -eventType "Information" -eventID 1 -eventMessage `
                        "Finalizing Processing of pFolder"
            Log-Finish -LogPath $sLogFile
            
            ## Send Email if Action is Done
            if ( $sendEmail -eq "True" ) {
                Log-Email -LogPath $sLogFile -EmailFrom $appSettings["from"] -EmailTo $appSettings["to"] -EmailSubject $appSettings["subject"]
            }
        }
        "TEST" {
            function StringVersions {
                param([array]$inputString)
                  $obj = New-Object PSObject
                  $obj | Add-Member NoteProperty Folder($inputString.Folder)
                  $obj | Add-Member NoteProperty Quota(convertTemplateToMB -qName $inputString.Quota)
                  $obj | Add-Member NoteProperty Action($inputString.Action)
                  Write-Output $obj
            }
            for ( $x=0; $x -lt $dActions.Count; $x++ ){
                StringVersions $dActions[$x]
            }
        }
    }
}