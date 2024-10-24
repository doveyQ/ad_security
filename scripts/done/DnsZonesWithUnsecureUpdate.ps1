[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 85
    UUID = '3a1e0f73-4c81-4192-87f7-38465dd18ce0'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000085'
    Name = 'Unsecured DNS configuration'
    ScriptName = 'DnsZonesWithUnsecureUpdate'
    Description = 'This indicator looks for DNS zones configured with ZONE_UPDATE_UNSECURE, which allows updating a DNS record anonymously.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'An attacker could leverage this exposure to arbitrarily add a new DNS record or replace an existing record to spoof a management interface, then wait for incoming connections in order to steal credentials.'
    ResultMessage = 'Found {0} DNS zones configured with ZONE_UPDATE_UNSECURE.'
    Remediation = 'Reconfigure DNS zones to only allow secure updates using the following command: dnscmd <servername> /Config <zone> /AllowUpdate 2'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ZoneName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_dnszone_bad_prop') }
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
$failedZones = 0

try {
    $dnsServers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

    foreach ($dnsServer in $dnsServers) {
        try {
            $zones = Get-DnsServerZone -ComputerName $dnsServer

            foreach ($zone in $zones) {
                if ($zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                    $outputObject = [PSCustomObject]@{
                        DistinguishedName = $zone.DN
                        ZoneName = $zone.ZoneName
                    }
                    [void]$outputObjects.Add($outputObject)
                    $failedZones++
                }
            }
        } catch {
            Write-Warning "Failed to check DNS zones on server: $dnsServer. Error: $_"
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    }
    else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = 'No DNS zones configured with ZONE_UPDATE_UNSECURE found.'
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
