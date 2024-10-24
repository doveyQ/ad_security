# This script checks for well-known privileged SIDs in users' sIDHistory attribute.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 23
    UUID = '78a9064a-f3a0-4420-ab9d-2db003d6f4b4'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000023'
    Name = 'Well-known privileged SIDs in sIDHistory'
    ScriptName = 'SIDHistoryPrivilegedSID'
    Description = 'This indicator checks security principal sIDHistory for well-known privileged SIDs.'
    Weight = 10
    Severity = 'Critical'
    ResultMessage = 'Found {0} objects with privileged SIDs inside their sIDHistory.'
    Remediation = 'Review the list and remove SIDs from the sIDHistory attribute if not explicitly required for migration.'
    Types = @('IoC')
    DataSources = @('AD.LDAP')
}

$outputObjects = [System.Collections.ArrayList]@()

$domainSID = (Get-ADDomain $DomainName).DomainSID
$privilegedSIDs = @(
    "$domainSID-500", # Domain Administrator
    "$domainSID-502", # KRBTGT
    "$domainSID-512", # Domain Admins
    "$domainSID-515", # Domain Computers
    "$domainSID-516", # Domain Controllers
    "$domainSID-517", # Cert Publishers
    "$domainSID-518", # Schema Admins (root domain)
    "$domainSID-519", # Enterprise Admins (root domain)
    "$domainSID-521", # Read-Only Domain Controllers
    "$domainSID-498", # Enterprise Read-Only Domain Controllers
    "$domainSID-553", # RAS and IAS Servers
    "S-1-5-32-544",   # BUILTIN/Administrators
    "S-1-5-18",       # SYSTEM (non-domain specific)
    "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
    "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
    "S-1-5-7",        # ANOYMOUS LOGON
    "S-1-5-9"         # Enterprise Domain Controllers
)

$adminSIDs = $privilegedSIDs | ForEach-Object { New-Object System.Security.Principal.SecurityIdentifier $_ }

try {
    if (-not (Get-ADDomain $DomainName -ErrorAction SilentlyContinue)) {
        throw "Domain '$DomainName' is unavailable."
    }

    $sIDHistoryUsers = Get-ADUser -Filter * -Properties sIDHistory -Server $DomainName | Where-Object { $_.sIDHistory.Count -gt 0 }

    foreach ($user in $sIDHistoryUsers) {
        $matchedSIDs = @()
        foreach ($sid in $user.sIDHistory) {
            $SIDobject = New-Object System.Security.Principal.SecurityIdentifier $sid
            if ($SIDobject -in $adminSIDs) {
                $matchedSIDs += $SIDobject.Value
            }
        }
        if ($matchedSIDs.Count -gt 0) {
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $user.DistinguishedName
                SIDHistory = $matchedSIDs -join ';'
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
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No privileged SIDs found in sIDHistory."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res