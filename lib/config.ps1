<#
.SYNOPSIS
    Get config from XML

.DESCRIPTION
    Get content from XML file and put in array
    
.PARAMETER path
    Mandatory. Source of config

.INPUTS
    Parameters above

.OUTPUTS
    None

.NOTES
	Version: 		1.0
    Author: 		Andreas Hansen
    Creation Date:	24/02/2014
    Purpose/Change:	Creat array from XML file
#>

Param ($path = $(throw "You must specify a config file"))
$global:appSettings = @{}
$config = [xml](get-content $path)
foreach ($addNode in $config.configuration.appsettings.add) {
    if ($addNode.Value.Contains(�,�)) {
        # Array case
        $value = $addNode.Value.Split(�,�)
        for ($i = 0; $i -lt $value.length; $i++) { 
            $value[$i] = $value[$i].Trim() 
        }
    } else {
        # Scalar case
        $value = $addNode.Value
    }
    $global:appSettings[$addNode.Key] = $value
}