# This script checks for changes to the Default Domain Policy and Default Domain Controllers Policy in the last 7 days

[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 48
    UUID = '9094ccca-30b3-4add-bfbb-0836aa9f074e'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000048'
    Name = 'Changes to Default Domain Policy or Default Domain Controllers Policy in the last 7 days'
    ScriptName = 'ChangesToDomainOrDCPolicies'
    Description = 'The Default Domain Policy and Default Domain Controllers Policy GPOs are special objects within AD, and control domain-wide and Domain Controller wide security settings. This indicator looks for changes to these two special GPOs within the last 7 days.'
    Weight = 4
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 4
    LikelihoodOfCompromise = 'Changes to the Default Domain Policy or Default Domain Controllers Policy should be accounted for by the administrators. If the change can not be accounted for, investigate the change looking for potential weakening of security posture and why the change was made.'
    ResultMessage = 'Found {0} sensitive policies in the organization that have been changed in the last {1} days.'
    Remediation = 'Review the changes and ensure that any changes to these two GPOs have gone through well-known change processes and that any changes made to these GPOs are well-documented. Investigate any undocumented changes.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement', 'Persistence') }
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
    $daysToCheck = 7
    $dateThreshold = (Get-Date).AddDays(-$daysToCheck)

    $gpos = Get-GPO -All -Domain $DomainName | Where-Object { 
        $_.DisplayName -in @('Default Domain Policy', 'Default Domain Controllers Policy') -and 
        $_.ModificationTime -ge $dateThreshold 
    }

    foreach ($gpo in $gpos) {
        $outputObject = [PSCustomObject]@{
            GPOName        = $gpo.DisplayName
            LastModified   = $gpo.ModificationTime
            Version        = $gpo.Version
        }
        [void]$outputObjects.Add($outputObject)
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = 'Failed'
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count, $daysToCheck
            ResultObjects   = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status         = 'Passed'
            ResultMessage  = "No changes to sensitive policies in the last $daysToCheck days."
        }
    }
} catch {
    $res.Status        = 'Error'
    $res.ResultMessage = $_.Exception.Message
}

return $res
