### Helper classes
class NcentralScheduledTaskCredential {
    [string]$type
    [string]$username
    hidden [string]$password

    ### Constructor
    NcentralScheduledTaskCredential([string]$type, [string]$username, [securestring]$password) {
        $decryptedpwd = ([Net.NetworkCredential]::New('', $password)).password
        if ($type -notin @('LocalSystem','CustomCredentials', 'DeviceCredentials')) {
            throw ("Invalid type {0}" -f $type)
        }
        if (($type -eq 'LocalSystem' -or $type -eq 'DeviceCredentials') -and ($username.length -ne 0 -or $decryptedpwd.length -ne 0)) {
            throw ("Type is {0}, but username and/or password also given" -f $type)
        }
        if ($type -eq 'CustomCredentials' -and $username.length -eq 0 -and $decryptedpwd.length -eq 0) {
            throw ("Type is {0}, but username and/or password are not given" -f $type)
        }
        $this.type = $type
        if ($type -eq 'CustomCredentials') {
            $this.username = $username
            $this.password = $decryptedpwd
        } else {
            $this.username = $null
            $this.password = $null
        }
    }
}

class NcentralScheduledTaskParameter {
    [string]$name
    [string]$value

    NcentralScheduledTaskParameter([string]$name,[string]$value) {
        if ($null -eq $name) {
            throw ("name should not be null")
        }
        $this.name = $name
        $this.value = $value
    }
}

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

### Main class
class NcentralClass {
    [string]$APIHost = $null
    [bool]$IsConnected = $false
    [string]$ErrorText = $null
    hidden [NcentralToken]$accesstoken = $null
    hidden [NcentralToken]$refreshtoken = $null
    [string[]]$ApiEndpoints = $null

    ### Functions

    ### Check if an endpoint is available
    [bool]TestEndpoint($Api) {
        foreach ($endpoint in $this.ApiEndpoints) {
            if ($Api -match "^$endpoint") {
                return $true
            }
        }
        return $false
    }

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
            Write-Verbose "Token is no longer valid. Trying to refresh"
        }

        ### Try to refresh
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
        if ($false -eq $this.TestEndpoint($Api)) {
            throw ("The endpoint for API call '{0}' is not available in the list of available endpoints '{1}'" -f $API, ($this.ApiEndpoints -join "', '"))
        }
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

    ###
    [pscustomobject]GetRaw([string]$Api) {
        if ($false -eq $this.TestEndpoint($Api)) {
            throw ("The endpoint for API call '{0}' is not available in the list of available endpoints '{1}'" -f $API, ($this.ApiEndpoints -join "', '"))
        }
        $this.RefreshTokens()

        $header = @{
            Authorization = ("{0} {1}" -f $this.accesstoken.type, $this.accesstoken.token)
            'Content-Type' = "application/json"
        }
        $URI = "https://{0}/api/{1}" -f $this.APIHost, $Api
        try {
            $result = Invoke-Restmethod -Uri $URI -Headers $header
            return $result
        }
        catch {
            throw ("Error invoking GET to URL $URI")
        }
    }

    ### Used for POST requests
    ### The access token is refreshed if necessary
    ### Returns an array of objects
    [System.Collections.ArrayList]Post([string]$API, [System.Collections.HashTable]$Params) {
        if ($false -eq $this.TestEndpoint($Api)) {
            throw ("The endpoint for API call '{0}' is not available in the list of available endpoints '{1}'" -f $API, ($this.ApiEndpoints -join "', '"))
        }
        $this.RefreshTokens()
        
        $result = [System.Collections.ArrayList]@()
        $header = @{
            Authorization = ("{0} {1}" -f $this.accesstoken.type, $this.accesstoken.token)
            'Content-Type' = "application/json"
        }
        $body = ConvertTo-Json -InputObject $Params -Depth 99 -Compress
        $URI = ("https://{0}/api/{1}" -f $this.APIHost, $Api)
        Write-Verbose ("Calling URL {0} with body {1}" -f $URI, $body)
        try {
            $tmp = Invoke-RestMethod -URI $URI -Method Post -Headers $header -Body $body -ContentType "application/json"
            $result.add($tmp)
        }
        catch {
            throw("POST to URL {0} resulted in error {1}" -f $URI, $Error[0].Exception.Message)
        } 
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
            ### Add the available endpoints to the connection object
            $apiinfo = Invoke-RestMethod -Uri ("https://{0}/api" -f $this.ApiHost)
            $properties = ($apiinfo._links | get-member | Where-Object { $_.memberType -eq 'NoteProperty' }).name | Where-Object { $_ -ne 'root' }
            $root = $apiinfo._links.root
            $this.ApiEndpoints = $properties | ForEach-Object { $apiinfo._links.$_ -replace "^$root/",""  }
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
        [parameter(Mandatory=$true)][Alias('Token')][securestring]$Key,
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
    Nothing.

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
    Get N-central server information

    .DESCRIPTION
    Get N-central server information.

    .EXAMPLE
    Get-NcentralServerInfo
#>
function Get-NcentralServerInfo {
    Param()

    Test-NcentralConnection
    $Global:_NcentralSession.GetRaw("server-info")
}

<#
    .SYNOPSIS
    Get N-central server health

    .DESCRIPTION
    Get information about the server health of N-central

    .OUTPUTS
    Information about the server health

    .EXAMPLE
    Get-NcentralServerHealth
#>
function Get-NcentralServerHealth {
    Param()

    Test-NcentralConnection
    $Global:_NcentralSession.GetRaw("health")
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

    .PARAMETER DeviceName
    Only devices matching the regular expression DeviceName are returned.

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

    .EXAMPLE
    Get-NcentralDevice -DeviceName SQL

    Gets all devices with 'SQL' in the name

    .EXAMPLE
    Get-NcentralDevice -DeviceName '^SQL'

    Gets all devices where the name starts with SQL
#>
function Get-NcentralDevice {
    [CmdletBinding(DefaultParametersetName='All')]
    Param(
        [parameter(Mandatory=$false, ParameterSetName='All')][switch]$All = $true,
        [parameter(Mandatory=$false, ParameterSetName='DeviceName', ValueFromPipeLine=$true)][string[]]$DeviceName,
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
                $devices = $Global:_NcentralSession.Get($API)
                $allDevices.AddRange($devices)
            }
            'Customer' {
                $API = "devices"
                $devices = $Global:_NcentralSession.Get($API)
                $alldevices.AddRange($devices)
            }
            'Device' {
                foreach ($d in $DeviceId) {
                    $API = ("devices/{0}" -f $d)
                    if ($scheduledTasks) {
                       $API = ("{0}/scheduled-tasks" -f $API)
                    }
                    $devices = $Global:_NcentralSession.Get($API)
                    $alldevices.AddRange($devices)
                }
            }
            'DeviceName' {
                $API = "devices"
                $devices = $Global:_NcentralSession.Get($API)
                $filter = $DeviceName -join '|'
                Write-Verbose ("Filtering using filter {0}" -f $filter)
                foreach ($d in $devices) {
                    if ($d.longname -match $filter) {
                        $alldevices.Add($d) | Out-Null
                    }
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
    Get-NcentralCustomer -CustomerName "ORGANISATION" | get-ncentraldevice | get-ncentraldevice -scheduledtasks | Get-NcentralScheduledTask

    Get the 'ORGANISATION' customer, get all devices in this organisation, get all scheduled tasks for this organisation, and return basic information on these scheduled tasks

    .EXAMPLE
    Get-NcentralCustomer -CustomerName "ORGANISATION" | get-ncentraldevice | get-ncentraldevice -scheduledtasks | Get-NcentralScheduledTask -Status -Details
    Get the 'ORGANISATION' customer, get all devices in this organisation, get all scheduled tasks for these devices, and return detailed status information on these scheduled tasks
#>
function Get-NcentralScheduledTask {
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

<#
    .SYNOPSIS
    Create a N-central scheduled task credential object

    .DESCRIPTION
    When creating a new scheduled task via New-NcentralScheduledTask, a credential object is needed. This function creates this object.

    .PARAMETER LocalSystem
    Create a LocalSystem credential object

    .PARAMETER DeviceCredentials
    Create a DeviceCredentials credential object

    .PARAMETER CustomCredentials
    Create a custom credentials object. A username and password are also needed when creating this type of credential
    
    .PARAMETER Username
    The username for a custom credentials object.

    .PARAMETER Password
    The password for a custom credentials object.

    .EXAMPLE
    $cred = New-NcentralScheduledTaskCredential -LocalSystem

    .EXAMPLE
    $cred = New-NcentralScheduledTaskCredential -CustomCredentials -Username MyUser -Password (Read-Host -AsSecureString)
#>
function New-NcentralScheduledTaskCredential {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, ParameterSetName="LocalSystem")][switch]$LocalSystem,
        [parameter(Mandatory=$true, ParameterSetName="DeviceCredentials")][switch]$DeviceCredentials,
        [parameter(Mandatory=$true, ParameterSetName="CustomCredentials")][switch]$CustomCredentials,
        [parameter(Mandatory=$true, ParameterSetName="CustomCredentials")][string]$Username,
        [parameter(Mandatory=$true, ParameterSetName="CustomCredentials")][securestring]$Password
    )

    Test-NcentralConnection
    Write-Verbose "type = $($PSCmdlet.ParameterSetName)"
    Write-Verbose "Username = $Username"
    Write-Verbose "Password = $Password"
    return [NcentralScheduledTaskCredential]::New($PSCmdlet.ParameterSetName, $Username, $Password)
}

<#
    .SYNOPSIS
    Create a N-central scheduled task parameters object

    .DESCRIPTION
    When creating a new N-central scheduled task, some tasks require extra parameters. With this function, you can create those parameters

    .PARAMETER Name
    One or more parameter names. The number of names should match the number of values.

    .PARAMETER Value
    One or more parameter values. The number of values should match the number of values.

    .EXAMPLE
    $params = New-NcentralScheduledTaskParameter -Name 'CountFile', 'Folder' -Value '*','C:\Temp'
#>
function New-NcentralScheduledTaskParameter {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)][string[]]$Name,
        [parameter(Mandatory=$true)][string[]]$Value
    )

    $Count = ($Name | Measure-Object).count
    if (($Value | Measure-Object).count -ne $Count) {
        throw ("The Name and Value arrays should have the same number of elements")
    }
    return 0..($Count-1) | ForEach-Object { [NcentralScheduledTaskParameter]::New($Name[$_], $Value[$_]) }
}

<#
    .SYNOPSIS
    Create a direct support task on one or more devices

    .DESCRIPTION
    Create a direct support task on one or more devices.
    If you use the pipeline to create multiple support tasks, the device ID is added to the task name in order to create unique names.

    .INPUTS
    A devicelist generated with Get-NcentralDevice

    .OUTPUTS
    An array of task details

    .NOTES
    If you get a 403 error code, check if the script repository with ID itemId is enabled for API access
    If you get a 500 error code, check if the name you are using is unique
    
    .PARAMETER TaskName
    The name of the support task. If you use the pipeline to create tasks for multiple devices, the device ID is added to the task name to create unique names.

    .PARAMETER DeviceId
    The ID of the device to create the task on. Don't use this parameter if you use the pipeline to define the devices on which the task should be created.

    .PARAMETER CustomerId
    The ID of the customer for the device. Don't use this parameter if you use the pipeline to define the devices on which the task should be created.

    .PARAMETER DeviceList
    An array of device objects. Don't use this parameter if you use the pipeline to define the devices on which the task should be created.

    .PARAMETER TaskType
    The type of the task.

    .PARAMETER ItemId
    The ID of the repository item. The item should be enabled for API access

    .PARAMETER Credential
    The credential used. If no credential is given, LocalSystem is used as credential

    .PARAMETER Parameters
    The parameters to be used, if needed.

    .LINK
    New-NcentralScheduledTaskCredential

    .LINK
    New-NcentralScheduledTaskParameter
    
    .EXAMPLE
    $name = "Randomtest--$(get-random -Minimum 10000000 -Maximum 99999999)"
    $cred = New-NcentralScheduledTaskCredential -DeviceCredentials
    $params = New-NcentralScheduledTaskParameter -Name "CountFile", "Folder" -Value "*", "C:\Windows"
    Get-NcentralDevice | New-NcentralScheduledTask -TaskName $name -TaskType AutomationPolicy -RepositoryId 1530938361 -Parameters $params -credential $cred

    Get all devices that the API account has access to, and create a support task on all of them. Because the devicelist is added through the pipeline, the device ID is added to the name.
#>
function New-NcentralScheduledTask {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)][string]$TaskName,
        [parameter(Mandatory=$true, ParameterSetName="DeviceId")][int]$DeviceId,
        [parameter(Mandatory=$true, ParameterSetName="DeviceId")][int]$CustomerId,
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="DeviceList")]$DeviceList,
        [parameter(Mandatory=$true)][ValidateSet('AutomationPolicy','AVDefenderFullScan','AVDefenderQuickScan','FileTransfer', 'Script', 'SoftwareDistribution')][string]$TaskType,
        [parameter(Mandatory=$true)][Alias("RepositoryId")][int]$ItemId,
        [parameter(Mandatory=$false)][NcentralScheduledTaskCredential]$credential = [NcentralScheduledTaskCredential]::New('LocalSystem',$null,$null),
        [parameter(Mandatory=$false)][NcentralScheduledTaskParameter[]]$Parameters = @()
    )

    begin {
        Test-NcentralConnection
        $allresult = [System.Collections.ArrayList]@()
    }

    process {
        $body = [System.Collections.Hashtable]@{}
        $body.Add("itemId",$ItemId) | Out-Null
        $body.Add("taskType", $TaskType) | Out-Null
        $body.add("credential",$Credential) | Out-Null
        $body.Add("parameters",$Parameters) | Out-Null
        if ($PSCmdlet.ParameterSetName -eq 'DeviceId') {
            $body.add("name", $TaskName) | Out-Null
            $body.add("deviceId", $DeviceId) | Out-Null
            $body.add("customerId", $CustomerId) | Out-Null
            $result = $global:_NcentralSession.Post("scheduled-tasks/direct", $body)
            $allresult.add($result) | Out-Null
        } else {
            $body.add("name", ("{0} - {1}" -f $TaskName, $DeviceList.deviceId)) | out-Null
            $body.add("deviceId", $DeviceList.deviceId) | Out-Null
            $body.add("customerId", $DeviceList.CustomerId) | Out-Null
            $result = $global:_NcentralSession.Post("scheduled-tasks/direct", $body)
            $allresult.add($result) | Out-Null
        }
    }

    end {
        return $allresult
    }
}
