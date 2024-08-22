# DeployTheNcentralAgent.ps1
#
# This script outputs the customer list, as well as the Registration Token for each customer.  The script prompts for parameters:
#    - N-Central server FQDN
#    - The JWT to be used to authenticate to N-central
#    - The CustomerID to be queried
#
# Created by: Chris Reid, Solarwinds MSP, with credit to Jon Czerwinksi and Kelvin Telegaar
# Date: Feb. 1st, 2021
# Version: 1.1

# Define the command-line parameters to be used by the script
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$serverHost,
    [Parameter(Mandatory = $true)][string]$JWT,
    [Parameter(Mandatory = $true)][int]$CustomerID
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$URI = ("https://{0}/api/auth/authenticate" -f $serverHost)
$postheader = [System.collections.Hashtable]@{}
$postheader.add('Authorization', ("Bearer {0}" -f $jwt)) | Out-Null

$tokens = Invoke-RestMethod -Uri $Uri -Method Post -Headers $postheader

$getheader = [System.collections.Hashtable]@{}
$getheader.add('Authorization', ("{0} {1}" -f $tokens.tokens.access.type, $tokens.tokens.access.token)) | Out-Null

$NcentralVersion = [version](Invoke-RestMethod -Uri ("https://{0}/api/server-info" -f $serverHost) -Method Get -Headers $getheader | Select-Object -ExpandProperty ncentral)
if (("{0}{1:d2}" -f $NcentralVersion.Major, $NcentralVersion.Minor) -lt '202404') {
    throw("This script requires N-central version 2024.4 or later")
}

$OrgUnitUrl = "https://{0}/api/org-units/{1}" -f $serverHost, $ID

$registrationtoken = (Invoke-RestMethod -Uri "$OrgUnitUrl/registration-token" -Method Get -Headers $getheader).data.registrationToken
if ($registrationtoken.length -eq 0) {
    throw("Error getting registration token for customer $ID")
}

Write-Output ("Customer ID is {0}, registration token is {1}" -f $ID, $registrationtoken)

# Let's see if the Windows Agent installer has already been placed in the %TEMP% directory
If (!(Test-Path -Path "C:\Temp\windowsAgentSetup.exe")) {
    Write-Output "The Agent installer was not found in C:\Temp. Attempting download from N-central."
    $URI = ("https://{0}/download/current/winnt/N-central/WindowsAgentSetup.exe" -f $serverHost)
    Invoke-WebRequest -Uri $URI -OutFile 'C:\Temp\WindowsAgentSetup.exe' -ProgressAction SilentlyContinue
}
Else {
    Write-Host "Agent installer is located in C:\Temp."
}
# Now that we've got the registration token for the specified customer, let's use it to install the Windows Agent
Write-Host "Initiating the agent install."
Start-Process -NoNewWindow -FilePath "C:\Temp\WindowsAgentSetup.exe" -ArgumentList "/s /v`" /qn CUSTOMERID=$SpecifiedCustomerID CUSTOMERSPECIFIC=1 REGISTRATION_TOKEN=$registrationtoken SERVERPROTOCOL=HTTPS SERVERADDRESS=$serverHost SERVERPORT=443`""