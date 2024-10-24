[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 65
    UUID = '31dcc5f6-ceb0-4132-a698-95bae64fe7df'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000065'
    Name = 'Principals with constrained delegation using protocol transition enabled for a DC service'
    ScriptName = 'ObjectsWithProtocolTransitionDC'
    Description = 'This indicator looks for principals (computers or users) that have constrained delegation using protocol transition defined against a service running on a DC.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Protocol transition (also known as T2A4D) allows any user to authenticate to a delegated service using any protocol such as NTLM. This allows the delegated service to request a TGS from Kerberos for any user without any proof such as that user''s corresponding TGT or TGS. If an attacker can create such a delegation for a service that they control or compromise an existing service, they can effectively gain a TGS for any user with privileges to the DC.'
    ResultMessage = 'Found {0} objects with protocol transition constrained delegation configured to Domain Controller.'
    Remediation = 'Remove any delegations that are defined against remote DC services.'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_delegation_t2a4d') }
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

    $dcs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Property DNSHostName, ServicePrincipalName -Server $DomainName
    if (-not $dcs) {
        Write-Error "No Domain Controllers found in the domain '$DomainName'."
        return
    }

    $dcSPNsWithoutDCName = @()
    foreach ($dc in $dcs) {
        if ($dc.ServicePrincipalName -and $dc.DNSHostName) {
            $hostname = $dc.DNSHostName.Split('.')[0]
            $spnsWithoutDC = $dc.ServicePrincipalName | Where-Object { $_ -notmatch "\/$hostname" }
            if ($spnsWithoutDC) {
                $dcSPNsWithoutDCName += $spnsWithoutDC
            }
        }
    }

    $results = Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like '*' } -Property msDS-AllowedToDelegateTo, DistinguishedName, TrustedToAuthForDelegation -SearchBase $DN -SearchScope Subtree

    foreach ($result in $results) {
        if ($result.TrustedToAuthForDelegation -eq $true) {
            $spns = $result."msDS-AllowedToDelegateTo"

    
            if (![string]::IsNullOrEmpty($spns)) {
                $thisOutput = [PSCustomObject]@{
                    DistinguishedName = $result.DistinguishedName
                    AllowedToDelegateTo = $spns -join "; "
                    EventTimestamp = (Get-Date)
                }
                $outputObjects += $thisOutput
            }
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
            ResultMessage = "No objects with protocol transition constrained delegation configured to Domain Controller found."
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
