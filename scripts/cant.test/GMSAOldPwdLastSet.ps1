# This script looks for computer objects that haven't changed their password in a while

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 72
    UUID = 'a7813b26-5472-4fbd-a6a4-1c93bfeb2784'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000072'
    Name = 'gMSA objects with old passwords'
    ScriptName = 'GMSAOldPwdLastSet'
    Description = 'This indicator looks for group managed service accounts that have not automatically rotated their passwords. These passwords should be changed automatically every 30 days by default.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'gMSA accounts should automatically rotate their passwords every 30 days. Objects that are not doing this could show evidence of tampering.'
    ResultMessage = 'Found {0} Group Managed Service Account objects whose password has not changed in the last {1} days.'
    Remediation = 'Managed Service Accounts'' passwords should be changed every 30 days. This is also the default setting. The returned accounts should be investigated for why their passwords were not changed. Note: The ''Active'' column shows if the account was active in the past 45 days.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Active'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'DaysSinceLastSet'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false }
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

$daysToRemove = 90
$activeDaysThreshold = 45
$pwdLastSetThreshold = (Get-Date).AddDays(-$daysToRemove)
$activeThreshold = (Get-Date).AddDays(-$activeDaysThreshold)


$outputObjects = @()

try {
    $gMSAAccounts = Get-ADUser -Filter 'objectClass -eq "msDS-GroupManagedServiceAccount"' -Properties PasswordLastSet, LastLogonTimestamp -Server $DomainName

    foreach ($account in $gMSAAccounts) {        
        $isActive = if ($account.LastLogonTimestamp) { $account.LastLogonTimestamp -ge $activeThreshold } else { $false }
        
        if ($account.PasswordLastSet -lt $pwdLastSetThreshold -and $isActive) {
            $outputObject = [PSCustomObject]@{
                Active              = $isActive
                DaysSinceLastSet    = (New-TimeSpan -Start $account.PasswordLastSet -End (Get-Date)).Days
                DistinguishedName    = $account.DistinguishedName
                PasswordLastSet      = $account.PasswordLastSet
            }
            $outputObjects += $outputObject
        }
    }

    if($outputObjects.Count -gt 0){
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No Group Managed Service Account objects whose password has not changed in the last $($daysToRemove) days found."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res