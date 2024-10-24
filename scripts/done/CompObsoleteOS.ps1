[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)


$Global:self = @{
    ID = 54
    UUID = 'a0d33c5f-fda5-4a06-9b80-5196e099131e'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000054'
    Name = 'Computers with older OS versions'
    ScriptName = 'CompObsoleteOS'
    Description = 'This indicator looks for machine accounts that are running versions of Windows older than Server 2012-R2 and Windows 8.1'
    Weight = 4
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 4
    LikelihoodOfCompromise = 'Computers running older and unsupported OS versions could be targeted with known or unpatched exploits.'
    ResultMessage = 'Found {0} computers in the organization that have obsolete OS.'
    Remediation = 'Where possible, update servers and workstations to later versions with better security features.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Active'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Enabled'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'LastLogonTimeStamp'; Type = 'String'; IsCollection = $false },
        @{ Name = 'OperatingSystem'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement', 'Persistence') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Software Update') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$daysToRemove = 30
$activeThreshold = (Get-Date).AddDays(-$daysToRemove)

$attributes = @("operatingsystem", "lastlogontimestamp", "pwdlastset", "useraccountcontrol")

$outputObjects = [System.Collections.ArrayList]@()

try {
    $DN = (Get-ADDomain -Server $DomainName).DistinguishedName

    $results = Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -SearchBase $DN -Properties $attributes |
    Where-Object {
        ($_.OperatingSystem -match "Windows Server 2008 R2|Windows Server 2008|Windows Server 2003 R2|Windows Server 2003|Windows 2000 Server") -or
        ($_.OperatingSystem -match "Windows XP|Windows Vista|Windows 7|Windows 8|Windows 2000 Professional")
    }
               

    foreach ($result in $results) {
        $uac = $result.UserAccountControl
        $pwdLastSet = $result.PasswordLastSet
        $lastLogonTimeStamp = $result.LastLogonTimeStamp
        $active = $false
        $enabled = $false

        if (($uac -band 0x2) -ne 0x2) { $enabled = $true }

        if ($null -ne $lastLogonTimeStamp ) {
            $lastLogonTimeStamp = [datetime]::FromFileTime([Int64]$lastLogonTimeStamp)
        }

        if ($pwdLastSet -ge $activeThreshold -or $lastLogonTimeStamp -ge $activeThreshold) { $active = $true }

        $thisOutput = [PSCustomObject][Ordered]@{
            DistinguishedName = $result.DistinguishedName
            LastLogonTimeStamp = if ($lastLogonTimeStamp) { $lastLogonTimeStamp } else { "Never" }
            PasswordLastSet = if ($pwdLastSet) { $pwdLastSet.ToUniversalTime() } else { "Never" }
            OperatingSystem = $result.OperatingSystem
            Active = $active
            Enabled = $enabled
        }

        [void]$outputObjects.Add($thisOutput)
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
            ResultMessage = "No computers with obsolete OS found."
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
