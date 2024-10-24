# This script checks the domain to determine if anonymous NSPI access to AD has been enabled.
[CmdletBinding()]
param(
    [Parameter(Mandatory, ParameterSetName='Execution')][string]$DomainName
)

$Global:self = @{
    ID = 52
    UUID = 'aace861d-9d2c-47df-9d3a-eb8f07008abb'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000052'
    Name = 'Anonymous NSPI access to AD enabled'
    ScriptName = 'AnonNSPIAccess'
    Description = 'Anonymous name service provider interface (NSPI) access on AD is a feature that allows anonymous RPC-based binds to AD. This indicator detects when NSPI access is enabled.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'NSPI access is rarely ever enabled so if you find it enabled, this should be a cause for concern.'
    ResultMessage = 'Found risky configuration in the forest that enables anonymous access to NSPI RPC operations.'
    Remediation = 'Disable anonymous name service provider interface (NSPI) access to AD unless it is absolutely needed. The dsHeuristics attribute on the CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=<forest_name> object should be set to disable anonymous access. For more information see <a href=`"https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5`">6.1.1.2.4.1.2 dSHeuristics</a>'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Initial Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_dsheuristics_bad') }
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
    $DN = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $searchParams = @{
        Filter = "objectClass -eq 'nTDSService'"
        Properties = @("whenChanged", "dsHeuristics")
        SearchBase = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DN"
    }

    $result = Get-ADObject @searchParams -ErrorAction Stop

    if ($result -and $result.dsHeuristics) {
        [array]$flag = $result.dsHeuristics.ToCharArray()

        if ($flag[6] -eq '2') {
            $outputObjects = [pscustomobject]@{
                DistinguishedName = $result.DistinguishedName
                DSHeuristics      = $result.dsHeuristics
                LastChanged       = $result.whenChanged
            }
        }
    }

    if ($outputObjects.Count -gt 0){
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [pscustomobject]@{
            Status = 'Passed'
            ResultMessage = 'No risky configuration in the forest that enables anonymous access to NSPI RPC operations found.'
        }
    }

} catch {
    $res = [pscustomobject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
