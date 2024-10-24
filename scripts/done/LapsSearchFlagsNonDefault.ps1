# This script looks for non-default searchFlags attribute on ms-mcs-admpwd

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 18
    UUID = '9ff5d86a-7523-423d-b657-ec28b36c904d'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000018'
    Name = 'Non default value on ms-Mcs-AdmPwd SearchFlags'
    ScriptName = 'LapsSearchFlagsNonDefault'
    Description = 'Some flags on the ms-Mcs-AdmPwd schema may inadvertently cause passwords to be visible to users allowing an attacker to use it as stealthy backdoor. This indicator looks for any changes to default searchFlags, which may create an exposure. Detection of changes to the default will result in a score of 80 for this indicator, signifying that a review should be conducted. Any removal of the default flags will result in a score of 0 due to their importance to security.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Even though schema changes are not common, a targeted schema change like this can leave the administrator passwords of 100s or 1000s of computers vulnerable to non-privileged users.'
    ResultMessage = 'Found non default flags on the mc-Mcs-AdmPwd searchFlags.'
    Remediation = 'Investigate the change of the mc-Mcs-AdmPwd attribute searchFlags and change it back to the default (904).'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'Flags'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') }
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

try {
    $schemaDN = "CN=Schema,CN=Configuration,DC=$($DomainName -replace '\.', ',DC=')"

    $searchFlags = Get-ADObject -SearchBase $schemaDN -Filter { Name -eq 'ms-Mcs-AdmPwd' } -Property searchFlags, whenChanged

    if ($searchFlags) {
        $flags = $searchFlags.searchFlags
        $lastEdited = $searchFlags.whenChanged 

        if ($flags -ne 904) {
            $output = [PSCustomObject]@{
                DistinguishedName = $searchFlags.DistinguishedName
                SearchFlags = $flags
                LastEdited = $lastEdited 
            }
            [void]$outputObjects.Add($output)
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
            ResultMessage = "No non-default flags found on the ms-Mcs-AdmPwd searchFlags."    
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
