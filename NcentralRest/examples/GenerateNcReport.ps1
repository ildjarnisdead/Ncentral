<#
.SYNOPSIS
    Generate a report of the NCs in the current directory.

.DESCRIPTION
    This script will generate a report of the NCs in the current directory. The report will be saved in the current directory as "NCReport.txt".

.AUTHOR
    Written by: Mohamed Salah
    Date: 2024-02-28
#>

Import-Module ./NcentralRest/NcentralRest.psm1

# Define the URL and token values for the API call
$ApiHost = "https://api.example.com/ncs"
$jwt = ""

# Generate a secure string from the token $jwt
$secureString = ConvertTo-SecureString -String $jwt -AsPlainText -Force
Connect-Ncentral -ApiHost $ApiHost -Key $secureString

# Get the list of Organization Units, and save the list to a Map collection using orgUnitId as the key
$page = 1
$pageSize = 500
$continue = $true
$orgUnitMap = @{}

do {
    $orgUnits = Get-NcentralOrgUnits -PageNumber $page -PageSize $pageSize
    foreach ($orgUnit in $orgUnits) {
        $orgUnitMap[[string]$orgUnit.orgUnitId] = $orgUnit
    }
    $page++
    $continue = $orgUnits.Count -eq $pageSize
} while ($continue)

# Print the orgUnitMap as JSON
# Write-Host "orgUnitMap: $(ConvertTo-Json $orgUnitMap)"

# Next, let's get the list of devices from the NC. devices will be aggregated based on the orgUnitId and saved to a Map collection
# The collection will then be used to generate CSV report
$page = 1
$pageSize = 500
$continue = $true
$aggregatedReport = @{}

# create a map to store business unit device count
$orgUnitDeviceCount = @{}
$orgUnitsProbeCount = @{}

# $shouldBreak = $false

do {
    $attemptCounter = 0
    $devices = $null

    do {
        try {
            $devices = Get-NcentralDevice -PageNumber $page -PageSize $pageSize
            $attemptCounter = 0
        }
        catch {
            $attemptCounter++
            if ($attemptCounter -eq 3) {
                Write-Host "Failed to retrieve devices. Skipping rest of loop."
                break
            }
            # Wait for 5 seconds before retrying
            Start-Sleep -Seconds 5
        }
    } while ($null -eq $devices)
    
    # Print debug info
    Write-Host "Page $page : $($devices.Count) devices"
    foreach ($device in $devices) {

        # Print device content as JSON
        # Write-Host "Device: $(ConvertTo-Json $device)"
        
        # set $orgUnitId to the string value of device.orgUnitId if defined, otherwise set it to the string value of device.customerId. If both are not defined, skip the device
        $orgUnitId = if ($device.orgUnitId) { [string]$device.orgUnitId } elseif ($device.customerId) { [string]$device.customerId } else { continue }
        
        
        $aggregatedStruct = $aggregatedReport[$orgUnitId]
        if ($null -eq $aggregatedStruct) {
            $BusinessUnit = $orgUnitMap[$orgUnitId]

            # Print debug info
            # Write-Host "Business Unit: $(ConvertTo-Json $BusinessUnit)"


            # Resolve so_id, so_name, customer_id, customer_name, site_id, site_name depending on $BusinessUnit's orgUnitType (SO/CUSTOMER/SITE)
            $parentId = [string]$BusinessUnit.parentId

            # Print orgUnitId, parentId, and orgUnitType
            # Write-Host "orgUnitId: $orgUnitId, parentId: $parentId, orgUnitType: $($BusinessUnit.orgUnitType)"

            if ($BusinessUnit.orgUnitType -eq "CUSTOMER") {
                $SoUnit = $orgUnitMap[$parentId]
                $Customer = $BusinessUnit
                $Site = $null
            }
            elseif ($BusinessUnit.orgUnitType -eq "SITE") {
                # Write-Host "Site: $(ConvertTo-Json $BusinessUnit)"
                $Site = $BusinessUnit
                $Customer = $orgUnitMap[$parentId]
                $SoUnit = $orgUnitMap[[string]$Customer.parentId]
            }
            else {
                # None of the above, so it's a SO ... skip it
                continue
            }

            # Print if we have reached this point
            # Write-Host "Customer ID: $($Customer.orgUnitId), SO Name: $($SoUnit.orgUnitName), Customer Name: $($BusinessUnit.orgUnitName)"

            # Business Unit (BU) -- Customer
            # Segment -- SO
            # N-Able ID -- Customer ID

            $aggregatedStruct = [PSCustomObject]@{
                'N-Able ID'                      = $Customer.orgUnitId
                'Segment'                        = $SoUnit.orgUnitName 
                'Business Unit Name'             = $BusinessUnit.orgUnitName
                'BU Windows Assets Discovered'   = 0
                'BU Total Assets'                = 0
                'BU Probe Count'                 = 0
                #'BU Discovery Started Date' =  Get-DiscoveryStartedDate($BusinessUnitProbe)
                'Site ID'                        = if ($Site) { $Site.orgUnitId } else { "" }
                'Site Name'                      = if ($Site) { $Site.orgUnitName } else { "" }
                'Site Windows Assets Discovered' = if ($Site) { 0 } else { "" }
                'Site Total Assets'              = if ($Site) { 0 } else { "" }
                'Site Probe Count'               = 0
                #'Site Discovery Started Date' =  Get-DiscoveryStartedDate($SiteProbe)
            }

            $aggregatedReport[$orgUnitId] = $aggregatedStruct
        }

        # Increment the device count for the at the Business Unit level
        $aggregatedStruct.'BU Total Assets'++
        

        if ($device.isProbe -eq $true) {
            $aggregatedStruct.'BU Probe Count'++
        }
        

        # Print debug info, including counting the devices
        # Write-Host "Device ID: $($device.deviceId), Customer ID: $($aggregatedStruct.'Customer ID'), Site ID: $($aggregatedStruct.'Site ID'), Customer Total Assets: $($orgUnitDeviceCount[$aggregatedStruct.'Customer ID'])"
        if ($aggregatedStruct.'Site ID') {
            # Write-Host "Device ID: $($device.deviceId), Site ID: $($aggregatedStruct.'Site ID'), Site Total Assets: $($aggregatedStruct.'Site Total Assets')"
            
            # Perform the counts at the site level
            # Increment the device count for the at the Site level
            $aggregatedStruct.'Site Total Assets'++

            # There will be multiple sites belonging to the same business unit, so we need to aggregate the counts at the business unit level
            $buId = [string]$aggregatedStruct.'N-Able ID'
            if ($null -eq $orgUnitDeviceCount[$buId]) {
                $orgUnitDeviceCount[$buId] = 0
            }
            if ($null -eq $orgUnitsProbeCount[$buId]) {
                $orgUnitsProbeCount[$buId] = 0
            }
            
            $orgUnitDeviceCount[$buId]++

            # if field discoveredName is not empty nor null, increment the Site 'Site Probe Count' count
            if ($device.isProbe -eq $true) {
                $orgUnitsProbeCount[$buId]++
            }


            # Print orgUnit counters
            # Write-Host "orgUnitDeviceCount: $(ConvertTo-Json $orgUnitDeviceCount)"
            # Write-Host "orgUnitsProbeCount: $(ConvertTo-Json $orgUnitsProbeCount)"

        }
        else {
            # Increment the device count for the at the Business Unit level
            $aggregatedStruct.'BU Total Assets'++
        }
    }
    $page++
    $continue = $devices.Count -eq $pageSize
} while ($continue)


# print orgUnitDeviceCount and orgUnitsProbeCount as JSON
# Write-Host "orgUnitDeviceCount: $(ConvertTo-Json $orgUnitDeviceCount)"
# Write-Host "orgUnitsProbeCount: $(ConvertTo-Json $orgUnitsProbeCount)"

# Write-Host "Aggregated Report: $(ConvertTo-Json $aggregatedReport)"

# Loop through values in $aggreatedReport and update the 'BU Probe Count' field with the value from $orgUnitsProbeCount
foreach ($orgUnitId in $aggregatedReport.Keys) {
    
    $aggregatedStruct = $aggregatedReport[$orgUnitId]
    # if the orgUnitId is not found in the aggregatedReport, print it as a warning
    if ($null -eq $aggregatedStruct) {
        Write-Host "Warning: orgUnitId $orgUnitId not found in the aggregatedReport"
        continue
    }
    # if Site ID is empty, then it's a customer. skip
    if (-not $aggregatedStruct.'Site ID') {
        continue
    }
    
    # If Site ID is not empty, then it's a site, so we need to update the "BU Total Assets" 'BU Probe Count' fields
    # resolve entry from orgUnitsProbeCount using N-Able ID
    $customerId = [string]$aggregatedStruct.'N-Able ID'


    
    if ($null -eq $orgUnitsProbeCount[$customerId]) {
        # This is an error. Print a warning, and continue
        Write-Host "Warning: customerId $customerId has no Probe Count calculated. skipping"
        continue
    }
    if ($null -eq $orgUnitDeviceCount[$customerId]) {
        # This is an error. Print a warning, and continue
        Write-Host "Warning: customerId $customerId has no Total Assets calculated. skipping"
        continue
    }

    # Update the 'BU Probe Count' field with the value from $orgUnitsProbeCount
    $aggregatedStruct.'BU Probe Count' = $orgUnitsProbeCount[$customerId]

    # Update the 'BU Total Assets' field with the value from $orgUnitDeviceCount
    $aggregatedStruct.'BU Total Assets' = $orgUnitDeviceCount[$customerId]
}

# Generate the report by converting aggregatedReport to array then exporting to a CSV file
$report = @()
foreach ($aggregatedStruct in $aggregatedReport.Values) {
    # Print debug info
    # Write-Host "Customer ID: $($aggregatedStruct.'Customer ID'), SO Name: $($aggregatedStruct.'SO Name'), Customer Name: $($aggregatedStruct.'Customer Name'), Customer Total Assets: $($aggregatedStruct.'Customer Total Assets'), Site ID: $($aggregatedStruct.'Site ID'), Site Name: $($aggregatedStruct.'Site Name'), Site Total Assets: $($aggregatedStruct.'Site Total Assets')"

    $report += $aggregatedStruct
}
# export to CSV
$report | Export-Csv -Path "NCReport $((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv" -NoTypeInformation -Encoding UTF8


# When done, disconnect from the API server
Disconnect-Ncentral