# This script checks if anonymous access to AD has been enabled for the specified domain.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DomainName
)

$Global:self = @{
    ID = 30
    UUID = '79d857a6-23a7-421d-a63d-5a2f9df5d080'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000030'
    Name = 'Anonymous access to Active Directory enabled'
    ScriptName = 'AnonAccessonAD'
    Description = 'It is possible, though not recommended, to enable anonymous access to AD. This indicator looks for the presence of the flag that enables anonymous access. Anonymous access would allow unauthenticated users to query AD.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Anonymous access to Active Directory allows an attacker to enumerate accounts and perform attacks like password spray, as well as to enumerate the domain to gather information that can model attack paths. This is a significant risk as the complexity of AD often presents many opportunities for attackers and anonymous access allows them an easy way to find such opportunities.'
    ResultMessage = 'Found risky configuration in the forest that enables anonymous access to LDAP operations.'
    Remediation = 'Disable anonymous access unless it is absolutely needed. The dsHeuristics attribute on the CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=<forest_name> object should be set to disable anonymous access. For more information see <a href=`"https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5`">6.1.1.2.4.1.2 dSHeuristics</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DSHeuristics'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Initial Access', 'Persistence', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_compatible_2000_anonymous') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$outputObjects = [System.Collections.ArrayList]@()
$failCount = 0

function Convert-ToDN {
    param (
        [string]$DomainName
    )
    $domainParts = $DomainName.Split('.')
    $distinguishedName = ''
    foreach ($part in $domainParts) {
        $distinguishedName += "DC=$part,"
    }
    return $distinguishedName.TrimEnd(',')
}

try {
    $DN = (Get-ADDomain -Identity $DomainName).DistinguishedName

    $configDN = "CN=Windows NT,CN=Services,CN=Configuration," + ($DN )

    $directoryService = Get-ADObject -Identity "CN=Directory Service,$configDN" -Properties dsHeuristics, whenChanged

    if ($directoryService) {
        $dsHeuristics = $directoryService.dsHeuristics
        if ($dsHeuristics -and $dsHeuristics.Length -ge 7 -and $dsHeuristics[6] -eq '2') {
            $failCount++
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $directoryService.DistinguishedName
                DSHeuristics      = $dsHeuristics
                LastChanged       = $directoryService.whenChanged
            }
            [void]$outputObjects.Add($thisOutput)
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
            Status        = 'Passed'
            ResultMessage = 'No anonymous access detected.'
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
