[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 51
    UUID = 'ff50af43-c9c8-41c6-987f-eaaaedbca25c'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000051'
    Name = 'Domains with obsolete functional levels'
    ScriptName = 'DomainObsoleteFunctionalLevel'
    Description = 'This indicator looks for AD domains that have a domain functional level set to Windows Server 2012 R2 or lower. These lower functional levels mean that newer security features available in AD cannot be leveraged. If the OS version of your domain controllers supports it, you should update to a newer domain functional level to take full advantage of security advancements in AD.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'While domain functional level is not a weakness in and of itself, an attacker with knowledge of functional levels can adjust their approach to take advantage of lack of security features in AD.'
    ResultMessage = 'Found {0} domains with low domain functionality level.'
    Remediation = 'Ensure that your AD domains are running at the highest functional level available for your OS version to ensure access to the latest security improvements. Also, consider upgrading the OS to 2016 or above, as new functional levels are available. See <a href=`"https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels`">Forest and Domain Functional Levels</a>.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'FunctionalLevel'; Type = 'String'; IsCollection = $false },
        @{ Name = 'FunctionalLevelInfo'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Reconnaissance') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Software Update') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_functional_level', 'vuln3_functional_level', 'vuln4_functional_level') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


try {
    $domainObj = Get-ADDomain -Identity $DomainName
    $domainFunctionalLevel = $domainObj.DomainMode

    $obsoleteFunctionalLevels = @('Windows2012Domain', 'Windows2012R2Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2003Domain', 'Windows2003R2Domain')
    foreach ($domain in $domainObj){
        $isObsolete = $obsoleteFunctionalLevels -contains $domainFunctionalLevel
        if ($null -ne $isObsolete){
            $outputObjects += [PSCustomObject]@{
                DomainName = $domain
                FunctionalLevel = $domainFunctionalLevel
                IsObsolete = $isObsolete
            }
        }
    }


    if ($isObsolete) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "The domain '$DomainName' is operating at a supported functional level: $domainFunctionalLevel."
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
