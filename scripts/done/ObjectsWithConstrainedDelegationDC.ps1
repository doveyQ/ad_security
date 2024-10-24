[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$DomainName
)

$Global:self = @{
    ID = 70
    UUID = '275b22b7-6386-46b8-a1bd-3f14965bf643'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000070'
    Name = 'Principals with constrained authentication delegation enabled for a DC service'
    ScriptName = 'ObjectsWithConstrainedDelegationDC'
    Description = 'This indicator looks for principals (computers or users) that have constrained delegation enabled for a service running on a DC. If an attacker can create such a delegation, they can authenticate to that service using any user that is not protected against delegation.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Constrained delegation allows a service to act on behalf of an authenticated user to another service. While this is sometimes necessary and requires the user to authenticate to the delegating service first, delegation to such services on domain controllers greatly increases risk. An attacker that is able to compromise such a service can significantly elevate their privileges in this way and infiltrate Active Directory.'
    ResultMessage = 'Found {0} objects with constrained delegation configured to Domain Controller.'
    Remediation = 'Remove any delegations, constrained or otherwise, that are defined against remote DC services.<br><br>MITRE D3fend based on the reference: <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank">audit-user-account-management of Microsoft</a>'
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
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') }
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
    foreach ($domain in $DomainName) {
        $searchParams = @{
            Properties = "msDS-AllowedToDelegateTo", "DistinguishedName"
            SearchBase = (Get-ADDomain $domain).DistinguishedName
        }

        $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

        $results = Get-ADObject -Filter * @searchParams

        if ($results) {
            foreach ($result in $results) {
                if ($result."msDS-AllowedToDelegateTo") {
                    $delegationTargets = $result."msDS-AllowedToDelegateTo" | ForEach-Object {
                        $_.Split('/')[1] 
                    }

                    $dcDelegations = $delegationTargets | Where-Object { $domainControllers -contains $_ }

                    if ($dcDelegations) {
                        $outputObjects += [PSCustomObject][Ordered] @{
                            DistinguishedName = $result.DistinguishedName
                            AllowedToDelegateTo = $result."msDS-AllowedToDelegateTo" -join "; "
                            EventTimestamp = (Get-Date)
                        }
                    }
                }
            }
        }
    }

    if ($outputObjects) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects with constrained delegation configured to Domain Controller services found."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
