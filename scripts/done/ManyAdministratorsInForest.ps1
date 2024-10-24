[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][string]$DomainName
)

$Global:self = @{
    ID = 64
    UUID = '9c9bfa49-9431-4043-a073-0f90f3008b54'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000064'
    Name = 'Forest contains more than 50 privileged accounts'
    ScriptName = 'ManyAdministratorsInForest'
    Description = 'This indicator counts the number of privileged user accounts defined in the forest, where 50 is deemed the upper limit for these types of accounts. A privileged account is defined as any user with the AdminCount attribute set to 1.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'In general, the more privileged accounts you have, the more opportunities there are for attackers to compromise one of those accounts. 50 is an arbitrary number, but the number should reflect the absolute maximum allowed. If business needs dictate many privileged accounts, consider implementing a tiered administration model to further isolate those privileged accounts and their potential impact from compromise.'
    ResultMessage = 'Found {0} privileged accounts in the forest.'
    Remediation = 'It''s always best to keep the number of privileged accounts as low as possible. Consider using solutions that allow for Just-in-time administration or implement admin tiering to ensure that only certain accounts can access domain controller, workstation and server resources. For more information on Admin Tiering <a href=`"https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model`">see this MS article.</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Reconnaissance') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_privileged_members') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$PrivilegedUserThreshold = 50
$outputObjects = [System.Collections.ArrayList]@()

try {
    $privilegedAccounts = Get-ADUser -Filter { AdminCount -eq 1 } -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree -Property SamAccountName
    $privilegedUserCount = $privilegedAccounts.Count

    foreach ($account in $privilegedAccounts) {
        $object = [PSCustomObject]@{
            DistinguishedName = $account.DistinguishedName
            SamAccountName = $account.SamAccountName
        }
        [void]$outputObjects.Add($object)
    }

    if ($privilegedUserCount -gt $PrivilegedUserThreshold) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    }
    else {
        $res = [PSCustomObject]@{
            Status        = "Passed"
            ResultMessage = "Found $privilegedUserCount privileged accounts in the domain '$DomainName', which is within the acceptable range."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status  = "Error"
        Message = $_.Exception.Message
    }
}

return $res
