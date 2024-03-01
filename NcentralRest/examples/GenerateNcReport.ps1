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

Connect-Ncentral -ApiHost $ApiHost -Key $jwt

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


# Next, let's get the list of devices from the NC. devices will be aggregated based on the orgUnitId and saved to a Map collection
# The collection will then be used to generate CSV report
$page = 1
$pageSize = 500
$continue = $true
$aggregatedReport = @{}

# Create a per-orgUnitId device counter
$orgUnitDeviceCount = @{}

do {
    $devices = Get-NcentralDevice -PageNumber $page -PageSize $pageSize
    # Print debug info
    # Write-Host "Page $page : $($devices.Count) devices"
    foreach ($device in $devices) {

        # Print device content as JSON
        # Write-Host "Device: $(ConvertTo-Json $device)"
        
        $orgUnitId = $device.customerId
        # Write-Host "Device ID: $($device.deviceId), Customer ID: $orgUnitId"
        
        $aggregatedStruct = $aggregatedReport[$orgUnitId]
        if ($null -eq $aggregatedStruct) {
            $BusinessUnit = $orgUnitMap[[string]$orgUnitId]

            # Print debug info
            # Write-Host "Business Unit: $(ConvertTo-Json $BusinessUnit)"


            # Resolve so_id, so_name, customer_id, customer_name, site_id, site_name depending on $BusinessUnit's orgUnitType (SO/CUSTOMER/SITE)
            if ($BusinessUnit.orgUnitType -eq "CUSTOMER") {
                $SoUnit = $orgUnitMap[$BusinessUnit.parentId]
                $Customer = $BusinessUnit
                $Site = $null
            }
            elseif ($BusinessUnit.orgUnitType -eq "SITE") {
                $Site = $BusinessUnit
                $Customer = $orgUnitMap[$BusinessUnit.parentId]
                $SoUnit = $orgUnitMap[$Segment.parentId]
            }
            else {
                # None of the above, so it's a SO ... skip it
                continue
            }

            # Print if we have reached this point
            # Write-Host "Customer ID: $($Customer.orgUnitId), SO Name: $($SoUnit.orgUnitName), Customer Name: $($BusinessUnit.orgUnitName)"

            $aggregatedStruct = [PSCustomObject]@{
                'Customer ID'           = $Customer.orgUnitId
                'SO Name'               = $SoUnit.orgUnitName 
                'Customer Name'         = $BusinessUnit.orgUnitName
                #'BU Windows Assets Discovered' = $BusinessUnitDeviceCount
                'Customer Total Assets' = 0
                #'BU Probe Count' = Get-ProbeCount($BusinessUnit.CustomerID)
                #'BU Discovery Started Date' =  Get-DiscoveryStartedDate($BusinessUnitProbe)
                'Site ID'               = if ($Site) { $Site.orgUnitId } else { "" }
                'Site Name'             = if ($Site) { $Site.orgUnitName } else { "" }
                #'Site Windows Assets Discovered' = $SiteDeviceCount
                'Site Total Assets'     = 0
                #'Site Probe Count' = Get-ProbeCount($Site.CustomerID)
                #'Site Discovery Started Date' =  Get-DiscoveryStartedDate($SiteProbe)
            }

            $aggregatedReport[$orgUnitId] = $aggregatedStruct
        }

        # Increment the device count for the at the Business Unit level
        $orgUnitDeviceCount[$aggregatedStruct.'Customer ID']++
        # Print debug info, including counting the devices
        # Write-Host "Device ID: $($device.deviceId), Customer ID: $($aggregatedStruct.'Customer ID'), Site ID: $($aggregatedStruct.'Site ID'), Customer Total Assets: $($orgUnitDeviceCount[$aggregatedStruct.'Customer ID'])"
        
        if ($aggregatedStruct.'Site ID') {
            $orgUnitDeviceCount[$aggregatedStruct.'Site ID']++
        }
    }
    $page++
    $continue = $devices.Count -eq $pageSize
} while ($continue)

# Now that we have the aggregated report, loop through Map. let's update the total assets count for each orgUnitId
foreach ($orgUnitId in $aggregatedReport.Keys) {
    $aggregatedStruct = $aggregatedReport[$orgUnitId]
    $aggregatedStruct.'Customer Total Assets' = $orgUnitDeviceCount[$aggregatedStruct.'Customer ID']
    if ($aggregatedStruct.'Site ID') {
        $aggregatedStruct.'Site Total Assets' = $orgUnitDeviceCount[$aggregatedStruct.'Site ID']
    }
}


# Generate the report by converting aggregatedReport to array then exporting to a CSV file
$report = @()
foreach ($aggregatedStruct in $aggregatedReport.Values) {
    Write-Host "Customer ID: $($aggregatedStruct.'Customer ID'), SO Name: $($aggregatedStruct.'SO Name'), Customer Name: $($aggregatedStruct.'Customer Name'), Customer Total Assets: $($aggregatedStruct.'Customer Total Assets'), Site ID: $($aggregatedStruct.'Site ID'), Site Name: $($aggregatedStruct.'Site Name'), Site Total Assets: $($aggregatedStruct.'Site Total Assets')"

    $report += $aggregatedStruct
}
# export to CSV
$report | Export-Csv -Path "NCReport $((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv" -NoTypeInformation -Encoding UTF8


# When done, disconnect from the API server
Disconnect-Ncentral