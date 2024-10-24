[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 14
    UUID = '16262280-22e2-40e2-a227-9934e63dadaa'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000014'
    Name = 'Users and computers with non-default Primary Group IDs'
    ScriptName = 'NonStandardPGID'
    Description = 'This indicator returns a list of users and computers whose Primary Group IDs (PGIDs) are not the defaults for domain users and computers.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'Modifying the Primary Group ID is a stealthy way for an attacker to escalate privileges.'
    ResultMessage = 'Found {0} objects with Primary Group ID of a group they are not a member of.'
    Remediation = 'Ensure these PGIDs are needed. When unneeded, change the Primary Group to Domain Users.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PrimaryGroupID'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GroupSamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_primary_group_id_1000', 'vuln3_primary_group_id_nochange') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$DN = (Get-ADDomain $DomainName).DistinguishedName
$outputObjects = [System.Collections.ArrayList]@()
$failedDomainCount = 0

try {
    $allUsers = Get-ADUser -Filter * -SearchBase $DN -Properties primaryGroupID

    foreach ($user in $allUsers) {
        $groupRID = $user.primaryGroupID
        $domainSID = (Get-ADDomain $DomainName).DomainSID

        $group = Get-ADGroup -Filter { SID -eq "$domainSID-$groupRID" } -Properties SamAccountName

        if ($group -and -not (Get-ADUser -Identity $user -Properties memberOf | Select-Object -ExpandProperty memberOf | Where-Object { $_ -eq $group.DistinguishedName })) {
            $thisOutput = [PSCustomObject][Ordered] @{
                DistinguishedName = $user.DistinguishedName
                PrimaryGroupID = $user.primaryGroupID
                GroupSamAccountName = $group.SamAccountName
            }
            [void]$outputObjects.Add($thisOutput)
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    }
    else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects with Primary Group ID of a group they are not a member of found."
        }
    }

    if ($failedDomainCount -gt 0) {
        $res.Status = 'Error'
        $res.ResultMessage += " Failed to run because the following domains were unavailable."
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
