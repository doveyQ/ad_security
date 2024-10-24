# This script looks for dangerous trust attributes
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 108
    UUID = 'ffa8305f-ff2e-4196-b980-8d7cafce849d'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000108'
    Name = 'Dangerous Trust Attribute Set'
    ScriptName = 'DangerousTrustAttributeSet'
    Description = 'This indicator identifies trusts set with either TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION or TRUST_ATTRIBUTE_PIM_TRUST. These bits will either allow a kerberos ticket to be delegated or reduce the protection that SID Filtering provides.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'An attacker that has compromised a remote domain can spoof any user or machine in the local domain. This can allow the attacker to access any resource as well as escalate their privileges, thus compromising the entire forest.'
    ResultMessage = 'Found {0} domains with dangerous trust attribute settings.'
    Remediation = 'Confirm that the trust attributes are configured as desired.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DangerousSetting'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'TrustName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Domain Trust Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_trusts_domain_notfiltered') }
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
$unavailableDomains = @()

try {
    if (-not (Get-ADDomain -Identity $DomainName -ErrorAction SilentlyContinue)) {
        $unavailableDomains += $DomainName
    } else {
        $results = Get-ADTrust -Filter * -Server $DomainName | 
            Where-Object { $_.TrustAttributes -band 1024 -or $_.TrustAttributes -band 2048 -or $_.TrustAttributes -band 1104 }

        foreach ($result in $results) {
            $dsetting = @()
            if ($result.TrustAttributes -band 1024) {
                $dsetting += "TRUST_ATTRIBUTE_PIM_TRUST"
            }
            elseif ($result.TrustAttributes -band 2048) {
                $dsetting += "TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"
            }
            elseif ($result.TrustAttributes -band 1104){
                $dsetting += "TRUST_ATTRIBUTE_PIM_TRUST & TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"
            }
            if ($dsetting.Count -gt 0) {
                $thisOutput = [PSCustomObject]@{
                    DomainName = $DomainName
                    TrustName = $result.Name
                    DangerousSetting = $dsetting -join ","
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
            ResultMessage = "No dangerous trust attributes found."
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
