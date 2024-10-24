# This script looks for disabled users with admincount=1

[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 39
    UUID = '87081486-fc4f-4027-842e-c5f17ec4f1bf'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000039'
    Name = 'Privileged users that are disabled'
    ScriptName = 'DisabledPrivilegedUsers'
    Description = 'This indicator looks for privileged user accounts, as indicated by their adminCount attribute set to 1, that are disabled. If a privileged account is disabled, it should be removed from its privileged group(s) to prevent inadvertent misuse.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'When a user is disabled, it tends to not be monitored as closely as active accounts. If this user is also a privileged user, then it becomes a target for takeover if an attacker can enable the account.'
    ResultMessage = 'Found {0} disabled users with adminCount attribute equal to 1.'
    Remediation = 'Ensure that privileged groups have only necessary users as members.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') }
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

try
{
    $privilegedDisabledAccounts = @("Administrators", "Domain Admins") | ForEach-Object {
        Get-ADGroupMember $_ | Where-Object { $_.objectClass -eq 'user' }
        } | Get-ADUser -Properties Enabled | Where-Object { $_.Enabled -eq $false } | 
        Select-Object -Unique DistinguishedName, Enabled


    if (!([string]::IsNullOrEmpty($privilegedDisabledAccounts))){
        foreach ($acc in $privilegedDisabledAccounts){
            $object = [PSCustomObject][Ordered] @{
                DistinguishedName = $acc.DistinguishedName
                Enabled = $acc.Enabled
            }
            [void]$outputObjects.Add($object)
        }

        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    }
    else {
        $res = [PSCustomObject][Ordered]@{
            Status = "Passed"
            ResultMessage = "No disabled privileged account found"
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
