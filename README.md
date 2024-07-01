# WARNING
Please note that I have very little time to work on this, this version is only working for 2023.9 and is left as a proof of concept, improvements and new features may or may not be added in the future.

# Powershell interface for the N-Central REST API

In version 2023.9.0.25, N-Able added a new REST API to N-Central.
For the old SOAP API there was already a PowerShell module, this module can be used to talk to the REST API.

# Supported versions

With each new N-central version, new API endpoints become available, and new functionalities become available in existing endpoints.
I will try to support at least 3 versions of N-central.
If you use a version of NcentralRest not meant for the version of N-central it was written for, you may get errors, strange results, or miss functionality.

| N-central version | NcentralRest version
|---|---
| 23.9.y.z | 1.0.x

# Classes

The module defines 4 new classes. All of them are for internal use of the module, but if you want to write your own code against the module classes, here are the definitions.

## NcentralClass

The central class. It holds the information on the N-central connection.

| Property | Hidden | Type | Description
|---|---|---|---
| ApiHost | No | String | The hostname of the N-central server. This must be a FQDN and the server must use a certificate that is trusted by PowerShell
| IsConnected | No | Bool | Whether the last connection attempt was successful or not. This does not mean that the access and/or refresh token are still valid
| ErrorText | No | String | If the last connection attempt was unsuccessful, this contains the reason why
| ApiEndpoints | No | String[] | The list of endpoints that are available on the N-central server.
| AccessToken | Yes | NcentralToken | The last used access token. It is possible that this token is no longer valid
| RefreshToken | Yes | NcentralToken | The last used refresh token. It is possible that this token is no longer valid

All public functions check whether the API endpoint is supported in the version of N-central you're connecting to, and take care of both refreshing the tokens and pagination.

| Method | Availability | Type | Parameters | Description
|---|---|---|---|---
| Get | Public | System.Collections.ArrayList | ApiEndpoint | Used for paginated GET requests.
| Get | Public | System.Collections.ArrayList | ApiEndpoint, Filter, Exactmatch | Used for paginated GET responses with a filter. The third parameter determines whether the filter is an exact match or a regular expression match
| GetOne | Public | pscustomobject | ApiEndpoint | Used for non-paginated GET requests.
| Post | Public | System.Collections.ArrayList | ApiEndpoint, Body | Used for POST requests.
| TestEndpoint | Private | Bool | ApiEndpoint | Tests whether the called endpoint is supported by the N-central server you're connected to
| RefreshTokens | Private | Void | None | Refreshes the access and refresh tokens when the access token is expired

## NcentralToken

The API works with two tokens: An access token (used in the Authorization header), and a refreshtoken (used to create a new access token when it has expired).

| Property | Hidden | Type | Description
|---|---|---|---
| Type | No | String | The type of the token, usually 'Bearer'
| ExpirySeconds | No | Int | The number of seconds that the token is valid
| ValidTo | No | Datetime | The date and time the token is valid to
| Token | Yes | String | The token itself

## NcentralScheduledTaskCredential

When creating a scheduled task, one of the parameters needed is a credential object. This class defines that credential object.

| Property | Hidden | Type | Description
|---|---|---|---
| type | No | String | The type of credential (Local System. Device credential or custom credential)
| username | No | String | Only valid for a custom credential
| password | Yes | String | Only valid for a custom credential. This is a plaintext password, not a securestring

## NcentralScheduledTaskParameter

When creating a scheduled task, some tasks require input parameters. This class defines the input parameter.

| Property | Hidden | Type | Description
|---|---|---|---
| name | No | String | The input parameter name
| value | No | String | The value of the input parameter

# Functions

The following functions are avaliable

## Connect-Ncentral

Creates a new N-central connection object. You can override the default expiry of the access token and the refresh token. The only requirement for
the expiries is that refreshexpiry must be at least 3 times accessexpiry.
After a successful connection, a global variable `$global:_NcentralServer` contains the connection information.

### Examples

```powershell
# The hostname to connect to
$ApiHost = "my.ncentral.server"
# The key is a securestring, if you have stored it in a vault use the syntax for your vault type to get it
$Key = Import-SecretFromVault "API key"

# Make the connection using the default expiries
Connect-Ncentral -ApiHost $ApiHost -Key $key
# Make the connection using custom expiries
Connect-Ncentral -ApiHost $ApiHost -Key $key -AccessExpiry 30 -RefreshExpiry 100
# This will result in an error, since the refresh expiry must be at least 3 times the access expiry
Connect-Ncentral -ApiHost $ApiHost -Key $key -AccessExpiry 30 -RefreshExpiry 30
```

## Disconnect-Ncentral

This removes the N-central connection object from the global variables. Note that this does **not** invalidate the tokens used in the connection!

### Examples

```powershell
# Disconnect from N-central
Disconnect-Ncentral
```

## Get-NcentralCustomer

Gets one or more customers. You can filter on one customer name.

### Examples

```powershell
# Get all customers
$allcustomers = Get-NcentralCustomer
# get one customer by customer name
$onecustomer = Get-NcentralCustomer -CustomerName ORGANISATION
```

## Get-NcentralDevice

Gets one or more devices. You can filter on customers or on device ID, either through the direct `-CustomerId` or `-DeviceId` parameter, or through the pipeline.
If you want to filter on device name, use `Get-NcentralDeviceByName`.

### Examples

```powershell
# Get all devices
$alldevices = Get-NcentralDevice
# Get all devices for one customer by using a customer object retrieved with Get-NcentralCustomer
$allcustomerdevices = $onecustomer | Get-NcentralDevice
# Get one device by ID
$onedevice = Get-NcentralDevice -DeviceId 1000
```

## Get-NcentralDeviceByName

Gets one or more devices based on a regular expression match on the longname property.

### Example

```powershell
# Get all devices with 'SQL' or 'DB' in the name
Get-NcentralDeviceByName -DeviceName 'SQL','DB'
# Get all devices that start with 'SQL' or end with 'DB'
'^SQL', 'DB$' | Get-NcentralDeviceByName
```

## Get-NcentralDeviceScheduledTask

Gets all direct support tasks on a device.

### Example

```powershell
# Get all scheduled tasks for all devices for customer 'ORGANISATION'
Get-NcentralCustomer -CustomerName "ORGANISATION" | Get-NcentralDevice | Get-NcentralDeviceScheduledTask
```

## Get-NcentralScheduledTask

Gets information on a direct support task.
By default, the direct support task settings are returned.
If you want the status of the direct support task, add the `-Status` switch.
If you want detailed status of the direct support task, also add the `-Details` switch.

Note that `-Details` without `-Status` is ignored.

### Example

```powershell
# Get information on one explicit task
Get-NcentralScheduledTask -TaskId 12345
# Get the detailed status for all scheduled tasks for device 'MyDevice'
Get-NcentralDeviceByName -DeviceName 'MyDevice' | Get-NcentralDeviceScheduldTask | Get-NcentralScheduledTask -Status -Details
```

## Get-NcentralServerHealth

Gets health status (boot time and current time) for the N-central server

### Example

```powershell
Get-NcentralServerHealth
```

## Get-NcentralServerInfo

Gets version information for the N-central server

### Example

```powershell
Get-NcentralServerInfo
```

## New-NcentralScheduledTaskCredential

When creating a direct support task, you need to provide the credential. This function will create that credential for you.

### Example

```powershell
### Create a localsystem credential
$localsystemcred = New-NcentralScheduledTaskCredential -LocalSystem
### Create a device credential
$devicecred = New-NcentralScheduledTaskCredential -DeviceCredentials
### Create custom credential
$password = Import-SecretFromVault "API key"
$customcred = New-NcentralScheduledTaskCredential -CustomCredentials -Username Foo -Password $password
```

## New-NcentralScheduledTaskParameter

When creating a direct support task for an item which requires one or more input parameters, you need to create the parameters object with this function.

### Example

```powershell
### Create an array of 3 input parameters
$params = New-NcentralScheduledTaskParameter -Name "a","b","c" -Value 1,2,3
### The number of arguments for Name and Value must be identical. The following call will result in an error
$params = New-NcentralScheduledTaskParameter -Name "a","b","c" -Value 1,2
```

## New-NcentralScheduledTask

Create a new direct support task on a device.
Default, it uses the LocalSystem credentials, if you want to override that you need to create an NcentralScheduledTaskCredential object for the `-Credential` parameter.
If you want to pass arguments to the task, you need to create an NcentralScheduledTaskParameter object array for the `-Parameters` parameter.
If you use the pipeline to feed the device(s) to this function, the device ID is added to the task name in order to create unique task names.
The item ID can be found in the Script/Software Repository in the 'Repository ID' column.

- Note that the repository item must be enabled for the API (the 'Enable API' column toggle must be set to **on**), otherwise you'll get a '403 Forbidden' error.
- Also note that the name must be unique. If a direct support task with that exact name already exists, you get a '500 Internal Server' error.

### Example

```powershell
### Item ID
$itemId = 1234567
### This item needs to be started with device credentials
$devicecred = New-NcentralScheduledTaskCredential -DeviceCredentials
### This item requires 3 parameters: a, b, and c
$params = New-NcentralScheduledTaskParameter -Name "a","b","c" -Value 1,2,3
### Create the direct support task on all SQL devices
get-ncentraldevicebyname -DeviceName SQL | New-NcentralScheduledTask -TaskName "SupportTask" -TaskType AutomationPolicy -ItemId $itemId -Parameters $params -Credential $devicecred
```

## Test-NcentralConnection

This function tests whether there is a connected N-central object. It does **not** test whether the tokens are still valid, this is done when performing a new call

### Example

```powershell
Test-NcentralConnection
```
