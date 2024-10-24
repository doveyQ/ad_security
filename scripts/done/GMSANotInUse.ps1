# This script checks for domains that don't have gMSA objects.

[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 84
    UUID = '93402830-3bdf-4086-8629-7bdc654651f9'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000084'
    Name = 'gMSA not in use'
    ScriptName = 'GMSANotInUse'
    Description = 'This indicator checks if there are enabled group Managed Service Account (gMSA) objects in the domain. For more information on gMSA see the Microsoft article: <a href="https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts" target="_blank">here.</a>'
    Weight = 4
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 4
    LikelihoodOfCompromise = 'The group Managed Service Account (gMSA) feature in Windows Server 2016 allows automatic rotation of passwords for service accounts, making them much more difficult for attackers to compromise. The feature should be used whenever possible for service accounts.'
    ResultMessage = 'Found {0} domains with no gMSA objects enabled.'
    Remediation = 'Group Managed Service Accounts should be used to protect service accounts. See description for more information.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {

    $gMSAResults = Get-ADServiceAccount -Server $DomainName -Filter 'objectclass -eq "msDS-GroupManagedServiceAccount"'

    foreach ($gMSA in $gMSAResults){
        if ($gmSA.Enabled -eq $false){
            $outputObjects.Add([PSCustomObject]@{ 
                DomainName = $DomainName 
                ServiceAccount = $gMSA.Name
                Enabled = $gMSA.Enabled
            })
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "All domains have gMSA objects enabled."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
