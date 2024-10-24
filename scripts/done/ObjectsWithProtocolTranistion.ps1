[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 58
    UUID = '74851f54-7ed4-456a-95c3-05e6090a9538'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000058'
    Name = 'Kerberos protocol transition delegation configured'
    ScriptName = 'ObjectsWithProtocolTranistion'
    Description = 'This indicator looks for services that have been configured to allow Kerberos protocol transition. This capability enables a delegated service to use any available authentication protocol. This means that compromised services can reduce the quality of their authentication protocol to something that is more easily compromised (e.g. NTLM).'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Protocol transition is not often used but when it is, it should be monitored closely for signs of abuse. In addition to compromising the authentication strength, this setting also allows attackers to request delegations with no authentication.'
    ResultMessage = 'Found {0} objects with protocol transition delegation configured.'
    Remediation = 'Validate that every delegation configured is known and necessary. Check if constrained kerberos could be configured instead of protocol transition.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AllowedToDelegateTo'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Lateral Movement', 'Privilege Escalation') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = @()

try {
    $DN = (Get-ADDomain $DomainName).DistinguishedName

    $computers = Get-ADComputer -Filter "msDS-AllowedToDelegateTo -like '*'" -Property msDS-AllowedToDelegateTo, TrustedToAuthForDelegation -SearchBase $DN -SearchScope Subtree
    $users = Get-ADUser -Filter "msDS-AllowedToDelegateTo -like '*'" -Property msDS-AllowedToDelegateTo, TrustedToAuthForDelegation -SearchBase $DN -SearchScope Subtree
    $serviceAccounts = Get-ADServiceAccount -Filter "msDS-AllowedToDelegateTo -like '*'" -Property msDS-AllowedToDelegateTo, TrustedToAuthForDelegation -SearchBase $DN -SearchScope Subtree

    $allObjects = @()

    foreach ($computer in $computers) {
        $allObjects += [PSCustomObject]@{
            Type = 'Computer'
            DistinguishedName = $computer.DistinguishedName
            AllowedToDelegateTo = $computer."msDS-AllowedToDelegateTo"
            TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
        }
    }

    foreach ($user in $users) {
        $allObjects += [PSCustomObject]@{
            Type = 'User'
            DistinguishedName = $user.DistinguishedName
            AllowedToDelegateTo = $user."msDS-AllowedToDelegateTo"
            TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
        }
    }

    foreach ($serviceAccount in $serviceAccounts) {
        $allObjects += [PSCustomObject]@{
            Type = 'ServiceAccount'
            DistinguishedName = $serviceAccount.DistinguishedName
            AllowedToDelegateTo = $serviceAccount."msDS-AllowedToDelegateTo"
            TrustedToAuthForDelegation = $serviceAccount.TrustedToAuthForDelegation
        }
    }

    $objectsWithProtocolTransition = $allObjects | Where-Object { $_.TrustedToAuthForDelegation -eq $true }

    foreach ($object in $objectsWithProtocolTransition){
        $outputObjects += [PSCustomObject]@{
            DistinguishedName = $object.DistinguishedName
            AllowedToDelegateTo = ($object.AllowedToDelegateTo -join "; ")
            EventTimestamp = (Get-Date)
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
            ResultMessage = "No objects with protocol transition delegation configured found."
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
