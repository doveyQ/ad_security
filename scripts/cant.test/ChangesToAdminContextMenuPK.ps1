# This script looks for any changes to adminContextMenu in the last 90 days

[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 82
    UUID = '4483e0c7-5ebe-4ee6-8845-731b2a1f9e06'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000082'
    Name = 'Changes to AD Display Specifiers in the past 90 days'
    ScriptName = 'ChangesToAdminContextMenuPK'
    Description = 'This indicator looks for changes made in the past 90 days to the adminContextMenu attribute on AD display specifiers. This attribute controls the right-click menus presented to users in the domain using MMC tools such as AD Users and Computers. Modifying these attributes can potentially allow attackers to get users to run arbitrary code if those menu options are clicked.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'Attackers may utilize context menus as a stealthy way of getting various users in a domain to execute code. Modifying this attribute requires special permissions granted by default only to Domain Admins and Enterprise Admins and also requires the user to click on the illicit context menu item. See the this blog post for additional information. (see this <a href="https://www.semperis.com/blog/active-directory-security-abusing-display-specifiers" target="_blank">writeup</a> for additional information).'
    ResultMessage = 'Found {0} changes to Admin Context Menu on Display Specifier in the last {1} days.'
    Remediation = 'Review the changes and ensure they are legitimate. It is also recommended to revert write permissions on Display Specifiers to default state (only privileged users have write permissions).'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Execution', 'Defense Evasion') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $results = @()

    $results = Get-ADObject -Filter "objectClass -eq 'displaySpecifiers'" -Property adminContextMenu | 
               Where-Object { $_.adminContextMenu -and (Get-ADObject $_.DistinguishedName -Properties whenChanged).whenChanged -ge (Get-Date).AddDays(-90) } | 
               Select-Object Name, whenChanged, adminContextMenu

    if ($null -ne $results) {
        $outputObjects = [System.Collections.ArrayList]@()

        foreach ($result in $results) {
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $result.DistinguishedName
                WhenChanged       = (Get-ADObject $result.DistinguishedName -Properties whenChanged).whenChanged
                AdminContextMenu  = $result.adminContextMenu
                DomainName        = $DomainName
            }
            [void]$outputObjects.Add($thisOutput)
        }

        $res = [PSCustomObject]@{
            Status         = 'Failed'
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects   = $outputObjects
            Remediation     = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = "No changes to Admin Context Menu on Display Specifier found in the last 90 days."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status        = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
