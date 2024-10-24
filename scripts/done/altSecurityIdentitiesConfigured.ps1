# This script looks for objects with altSecurityIdentities configured

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 102
    UUID = '59551a78-1f84-42fe-ad13-d38413d1c882'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000102'
    Name = 'Accounts with altSecurityIdentities configured'
    ScriptName = 'altSecurityIdentitiesConfigured'
    Description = 'It is possible to add values to the altSecurityIdentities attribute and essentially impersonate that account. The altSecurityIdentities attribute is a multi-valued attribute used to create mappings for X.509 certificates and external Kerberos accounts. This indicator checks for accounts with the altSecurityIdentities attribute configured.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'This type of attack may be easy to spot as it is rarely configured during normal operations. However, it is possible for this attribute to be configured genuinely.'
    ResultMessage = 'Found {0} account(s) with altSecurityIdentities configured.'
    Remediation = 'Remove any entries in altSecurityIdentities attributes that are not explicitly required.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AltCertificates'; Type = 'String'; IsCollection = $true },
        @{ Name = 'AltExternal'; Type = 'String'; IsCollection = $true },
        @{ Name = 'AltUnknown'; Type = 'String'; IsCollection = $true },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_delegation_a2d2') }
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
$res = [PSCustomObject]@{
    Status         = 'Not Executed'
    ResultMessage  = ''
    Remediation    = ''
}

try {
    $results = Get-ADUser -Server $DomainName -Filter { altSecurityIdentities -like "*" } -Properties altSecurityIdentities | Select-Object SamAccountName, DistinguishedName, altSecurityIdentities

    if ($null -ne $results) {
        foreach ($result in $results) {
            $configuredCertificates = [System.Collections.ArrayList]@()
            $configuredExternal = [System.Collections.ArrayList]@()
            $configuredUnknown = [System.Collections.ArrayList]@()

            # Categorize altSecurityIdentities values
            @($result.altSecurityIdentities).ForEach({
                if ($_.ToUpper().StartsWith("X509:")) {
                    [void]$configuredCertificates.Add($_.SubString(5))
                }
                elseif ($_.ToUpper().StartsWith("KERBEROS:")) {
                    [void]$configuredExternal.Add($_.SubString(9))
                }
                else {
                    [void]$configuredUnknown.Add($_)
                }
            })

            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $result.DistinguishedName
                AltCertificates   = $configuredCertificates
                AltExternal       = $configuredExternal
                AltUnknown        = $configuredUnknown
            }
            [void]$outputObjects.Add($thisOutput)
        }


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
            ResultMessage = "No account(s) with altSecurityIdentifies configured"
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
