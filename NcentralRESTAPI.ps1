### NcentralToken class
### Properties:
### type: The type of the token (at the moment only 'Bearer' is used)
### expirySeconds: The number of seconds the token is valid
### validTo: Calculated from the current time at creation and expirySeconds
### token: A hidden property with the actual token, in unencrypted format

class NcentralToken {
    [string]$type
    [int]$expirySeconds
    [datetime]$validTo
    hidden [string]$token

    NcentralToken ([string]$token, [string]$type, [int]$expirySeconds) {
        $this.type = $type
        $this.expirySeconds = $expirySeconds
        $this.token = $token
        $this.validTo = (Get-Date).AddSeconds($expirySeconds)
    }
}

### The class that holds the N-central connection
### Properties:
### APIHost: The DNS name (FQDN) of the API host.
### isConnected: Whether the last connection attempt was successful or not
### ErrorText: Information on the connection error if isConnected is false
### accesstoken: A hidden property with the access token. Uses the NcentralToken class
### refreshtoken: A hidden property with the refresh token. Uses the NcentralToken class

class NcentralClass {
    [string]$APIHost = $null
    [bool]$IsConnected = $false
    [string]$ErrorText = $null
    hidden [NcentralToken]$accesstoken = $null
    hidden [NcentralToken]$refreshtoken = $null

    ### Functions

    ### Before calling a GET or POST URL, the token must be checked for validity.
    ### If the current access token is still valid, nothing happens
    ### If the current access token is no longer valid, an attempt is made to use the refresh token to generate new access and refresh tokens
    ### If the refresh was successful, the access token and refresh token are updated
    ### If the refresh was unsuccessful, the Ncentral connection is invalidated, and the tokens are cleared in the connection object
    [void]RefreshTokens() {

        ### Test to see if the current token is still valid
        try {
            [System.Collections.HashTable]$header = @{}
            $header.add('Authorization',('{0} {1}' -f $this.accesstoken.type, $this.accesstoken.token))

            $validation = Invoke-RestMethod -Uri ("https://{0}/api/auth/validate" -f $this.APIHost) -Headers $header -ErrorAction Stop
            Write-Verbose "Token is still valid, not refreshing"
            return
        } catch {
        }

        ### Try to refresh
        Write-Verbose "Refreshing tokens"
        [System.Collections.HashTable]$header = @{}
        $header.Add('X-ACCESS-EXPIRY-OVERRIDE',('{0}s' -f $this.accesstoken.expirySeconds)) | Out-Null
        $header.Add('X-REFRESH-EXPIRY-OVERRIDE',('{0}s' -f $this.refreshtoken.expirySeconds)) | Out-Null
        try {
            $tokens = Invoke-Restmethod -Uri ("https://{0}/api/auth/refresh" -f $this.APIHost) -Method Post -Body $this.refreshtoken.token -Headers $header -ErrorAction Stop
            $this.accesstoken = [NcentralToken]::New($tokens.tokens.access.token, $tokens.tokens.access.type, $tokens.tokens.access.expirySeconds)
            $this.refreshtoken = [NCentralToken]::New($tokens.tokens.refresh.token, $tokens.tokens.refresh.type, $tokens.tokens.refresh.expirySeconds)
        }
        catch {
            $this.IsConnected = $false
            $this.accesstoken = $null
            $this.refreshtoken = $null
            $this.ErrorText = "The access token is no longer valid, and an attempt to renew it using the refresh token failed"
            throw("The access token is no longer valid, and an attempt to renew it using the refresh token failed")
        }

        return
    }

    ### Used for GET operations
    ### The access token is refreshed if necessary
    ### Returns an array of objects
    [System.Collections.ArrayList] Get([string]$Api) {
        $this.RefreshTokens()
        $URI = ("https://{0}/api/{1}" -f $this.APIHost, $Api)
        $continue = $true
        $result = [System.Collections.ArrayList]@()
        $header = @{
            Authorization = ("{0} {1}" -f $this.accesstoken.type, $this.accesstoken.token)
        }
        do {
            Write-Verbose "Calling URI $URI"
            Remove-Variable tmp -Force
            try {
                $tmp = Invoke-RestMethod -Uri $URI -Headers $header -Method GET
            } catch {
                throw ("Error invoking GET to URL $URI")
            }
            foreach ($d in $tmp.data) {
                $result.add($d) | Out-Null
            }
            if ($tmp._links.nextPage.length) {
                $URI = ("https://{0}{1}" -f $this.APIHost, $tmp._links.nextpage)
            } else {
                $continue = $false
            }
        } until ($false -eq $continue)
        return $result
    }

    ### Empty constructor, returns an error
    NcentralClass () {
        throw "Don't call New() without parameters!"
    }

    ### Full constructor.
    NcentralClass ([string]$ApiHost, [securestring]$Key, [int]$accessExpiry, [int]$refreshexpiry) {
        ### Default expiries
        if ($accessExpiry -le 0) {
            Write-Verbose "No accessexpiry given, or a negative value, setting to default value 3600"
            $accessExpiry = 3600
        }
        if ($refreshexpiry -le 0) {
            Write-Verbose "No refreshexpiry given, or a negative value, setting to default value 90000"
            $refreshexpiry = 90000
        }

        if ((3*$accessExpiry) -gt $refreshexpiry) {
            throw(("The refresh expiry ({0} seconds) should be at least 3 times the access expiry ({1} seconds), aborting" -f $refreshexpiry,$accessExpiry))
        }

        $this.APIHost = $ApiHost

        $jwt = ([Net.NetworkCredential]::New('', $key)).password
        $URI = ("https://{0}/api/auth/authenticate" -f $ApiHost)
        $postheader = [System.collections.Hashtable]@{}
        $postheader.add('Authorization', ("Bearer {0}" -f $jwt)) | Out-Null

        if (0 -ne $accessExpiry) {
            $postheader.add('X-ACCESS-EXPIRY-OVERRIDE',('{0}s' -f $accessExpiry)) | Out-Null
        }
        if (0 -ne $refreshexpiry) {
            $postheader.add('X-REFRESH-EXPIRY-OVERRIDE', ('{0}s' -f$refreshexpiry)) | Out-Null
        }
        Write-Verbose "URL = $URI"
        try {
            $tokens = Invoke-RestMethod -Uri $URI -Headers $postheader -Method Post
            $this.accesstoken = [NcentralToken]::New($tokens.tokens.access.token, $tokens.tokens.access.type, $tokens.tokens.access.expirySeconds)
            $this.refreshtoken = [NCentralToken]::New($tokens.tokens.refresh.token, $tokens.tokens.refresh.type, $tokens.tokens.refresh.expirySeconds)
            $this.IsConnected = $true

        } catch {
            $this.ErrorText = $Error[0].Exception.Message
            $this.IsConnected = $false
        }
    }
}

<#
    .SYNOPSIS
    Connect to N-central, using a JWT token
    
    .DESCRIPTION
    Before accessing the N-central REST API you need to connect to N-central, using a JWT token for an API-enabled account.
    MFA must be disabled on this account for this to work correctly.
    After a successful connection is made, a global variable _NcentralSession is created which holds information about the
    N-central connection, including the access and refresh tokens. These tokens are hidden by default in the object.

    .INPUTS
    Nothing. You need to pass the parameters in the invocation.

    .OUTPUTS
    Nothing, the N-central connection (if successful) is stored in a global variable.

    .LINK
    Test-NcentralConnection

    .LINK
    Disconnect-Ncentral

    .PARAMETER Key
    The JWT token used to generate the access and refresh token

    .PARAMETER ApiHost
    The DNS name (FQDN) of the API host.

    .PARAMETER accessexpiry
    By default, the access token is 3600 seconds (1 hour) valid. With this parameter you can override the default value.

    .PARAMETER refreshexpiry
    By default, the refresh token is 90000 seconds (25 hours) valid. With this parameter you can override the default value.
    The refresh expiry duration must be at least 3 times the access expiry duration

    .EXAMPLE
    $Key = Read-Host -AsSecureString "JWT token"
    Connect-Ncentral -Key $key -ApiHost ncentral.organisation.com
    Creates a connection to ncentral.organisation.com with default access token expiry and refresh token expiry duration.

    .EXAMPLE
    $Key = Read-Host -AsSecureString "JWT token"
    Connect-Ncentral -Key $key -ApiHost ncentral.organisation.com -accessexpiry 60 -refreshexpiry 600
    Creates a connection to ncentral.organisation.com with a non-default access token expiry and refresh token expiry duration.
#>
function Connect-Ncentral {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)][securestring]$Key,
        [parameter(Mandatory=$true)][string]$ApiHost,
        [parameter(Mandatory=$false)][int]$accessexpiry = $null,
        [parameter(Mandatory=$false)][int]$refreshexpiry = $null
    )

    $Global:_NcentralSession = [NcentralClass]::New($ApiHost, $Key, $accessexpiry, $refreshexpiry)
    if ($Global:_NcentralSession.IsConnected) {
        Write-Verbose ("Successfully connected to NCentralHost {0}" -f $ApiHost)
    } else {
        Write-Error ("Authentication failed to Ncentral Host {0} with error {1}" -f $ApiHost, $Global:_NcentralSession.ErrorText)
    }
}

<#
    .SYNOPSIS
    Test if there is a connected N-central object.
    
    .DESCRIPTION
    Test if there is a connected N-central object. Note that this does not check the validity of the access token and/or refresh token.

    .INPUTS
    Nothing. You need to pass the parameters in the invocation.

    .OUTPUTS
    An error when no valid N-central connection is found.
    No return value when a valid N-central connection is found.

    .LINK
    Connect-Ncentral

    .LINK
    Disconnect-Ncentral

    .EXAMPLE
    Test-NcentralConnection

    You need to call Connect-Ncentral first before using this function
    At C:\Scripts\Powershell\N-central\NcentralRESTAPI.ps1:192 char:9
    +         throw("You need to call Connect-Ncentral first before using t ...
    +         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : OperationStopped: (You need to cal...g this function:String) [], RuntimeException
        + FullyQualifiedErrorId : You need to call Connect-Ncentral first before using this function
#>    
function Test-NcentralConnection {
    [CmdletBinding()]
    Param()
    
    if ($null -eq $Global:_NcentralSession) {
        throw("You need to call Connect-Ncentral first before using this function")
    }
    if ($false -eq $Global:_NcentralSession.IsConnected) {
        throw("The connection to N-central failed, first create a successful connection")
    }
    return
}

<#
    .SYNOPSIS
    Remove the N-central connection
    
    .DESCRIPTION
    Removes the global N-central connection. Note that this does *NOT* invalidate the access tokens previously generated in the connection,
    it just removes the references to these tokens.

    .INPUTS
    Nothing.

    .OUTPUTS
    No return value, the global variable is removed

    .LINK
    Disconnect-Ncentral

    .LINK
    Connect-Ncentral

    .EXAMPLE
    Disconnect-Ncentral

#>  
function Disconnect-Ncentral {
    [CmdletBinding()]
    Param()

    Remove-Variable -Scope global -Name _NcentralSession -Force -ErrorAction SilentlyContinue
}

<#
    .SYNOPSIS
    gets all customers
    
    .DESCRIPTION
    Gets all customers that are visible for the N-central connection

    .INPUTS
    Nothing.

    .OUTPUTS
    An array of customer objects

    .PARAMETER All
    By default, all customers are returned

    .PARAMETER CustomerName
    Returns only the customer(s) with the matching name.

    .EXAMPLE
    Get-NcentralCustomer

#>  
function Get-NcentralCustomer {
    [CmdletBinding(DefaultParametersetName='All')]
    Param(
        [parameter(Mandatory=$false, ParameterSetName='All')][switch]$All = $true,
        [parameter(Mandatory=$True, ParameterSetName='Customer')][string]$CustomerName
    )

    Test-NcentralConnection
    $Customers = $Global:_NcentralSession.get("customers")
    if ($PSCmdlet.ParameterSetName -eq 'Customer') {
        $customers = $customers | Where-object { $_.customerName -eq $CustomerName }
    }
    return $Customers
}

<#
    .SYNOPSIS
    Gets device information

    .DESCRIPTION
    Gets device information.
    When passing a customer ID, only the devices belonging to that customer ID are returned
    When passing a device ID, only information for that device is returned.
    It's also possible to get the scheduled tasks associated with a device, the device ID is required in this case.

    .INPUTS
    A customer object from Get-NcentralCustomer

    .INPUTS
    An array of device objects from Get-NcentralDevice

    .OUTPUTS
    An array of devices

    .OUTPUTS
    An array of tasks if the ScheduledTasks parameter is given

    .PARAMETER All
    If no parameter is given, the 'All' switch parameter is assumed.

    .PARAMETER DeviceId
    A device ID (or a list of device IDs, possibly from objects from the pipeline).

    .PARAMETER scheduledTasks
    If this switch is given, instead of devices the list of scheduled tasks from the input devices are returned

    .PARAMETER CustomerId
    A customer ID to limit the returned objects

    .EXAMPLE
    Get-NcentralDevice

    Get all devices from the N-central server

    .EXAMPLE
    Get-NcentralCustomer -CustomerName "ORGANISATION" | Get-NcentralDevice | Get-NcentralDevice -scheduledTasks

    Get the customer 'ORGANISATION', get the devices associated with this customer, and then get the scheduled tasks for these devices
#>
function Get-NcentralDevice {
    [CmdletBinding(DefaultParametersetName='All')]
    Param(
        [parameter(Mandatory=$false, ParameterSetName='All')][switch]$All = $true,
        [parameter(Mandatory=$true, ParameterSetName='Device', ValueFromPipelineByPropertyName=$true)][int[]]$DeviceId,
        [parameter(Mandatory=$false, ParameterSetName='Device')][switch]$scheduledTasks,
        [parameter(Mandatory=$true, ParameterSetName='Customer', ValueFromPipelineByPropertyName=$true)][string]$CustomerId
    )

    begin{
        Test-NcentralConnection
        $alldevices = [System.Collections.ArrayList]@()
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'All' {
                $API = "devices"
                $devices = $Global:_NcentralSession.get($API)
                $allDevices.AddRange($devices)
            }
            'Customer' {
                $API = "devices"
                $devices = $Global:_NcentralSession.get($API)
                $alldevices.AddRange($devices)
            }
            'Device' {
                foreach ($d in $DeviceId) {
                    $API = ("devices/{0}" -f $d)
                    if ($scheduledTasks) {
                       $API = ("{0}/scheduled-tasks" -f $API)
                    }
                    $devices = $Global:_NcentralSession.get($API)
                    $alldevices.AddRange($devices)
                }
            }      
        }
    }

    end {
        return $alldevices
    }
}

<#
    .SYNOPSIS
    Gets information on scheduled tasks

    .DESCRIPTION
    Gets basic or detailed statuses for one or more scheduled tasks

    .INPUTS
    An array of tasks from Get-NcentralDevice -scheduledTasks

    .OUTPUTS
    An array of task details

    .PARAMETER TaskId
    One or more task IDs

    .PARAMETER Status
    Whether to return the task or the status of the task

    .PARAMETER Details
    If the status is requested, whether to return basic information or detailed information

    .EXAMPLE
    Get-NcentralCustomer -CustomerName "ORGANISATION" | get-ncentraldevice | get-ncentraldevice -scheduledtasks | Get-NcentralScheduledTaskStatus

    Get the 'ORGANISATION' customer, get all devices in this organisation, get all scheduled tasks for this organisation, and return basic information on these scheduled tasks

    .EXAMPLE
    Get-NcentralCustomer -CustomerName "ORGANISATION" | get-ncentraldevice | get-ncentraldevice -scheduledtasks | Get-NcentralScheduledTaskStatus -
#>
function Get-NcentralScheduledTaskStatus {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)][int[]]$TaskId,
        [parameter(Mandatory=$false)][switch]$Status = $false,
        [parameter(Mandatory=$false)][switch]$Details = $false
    )

    begin {
        Test-NcentralConnection
        $alltasks = [System.Collections.ArrayList]@()
    }

    process {
        foreach ($t in $TaskId) {
            $API = ("scheduled-tasks/{0}" -f $t)
            if ($true -eq $Status) {
                $API = ("{0}/status" -f $API)
                if ($true -eq $Details) {
                    $API = ("{0}/details" -f $API)
                }
            }
        }
        $tasks = $Global:_NcentralSession.get($API)
        $alltasks.AddRange($tasks)
    }
    
    end {
        return $alltasks
    }
}