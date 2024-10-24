[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 104
    UUID = 'c0c929cf-ab95-4d8f-975b-8193054f520b'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000104'
    Name = 'Changes to Pre-Windows 2000 Compatible Access Group membership'
    ScriptName = 'PreWin2KGroup'
    Description = 'This indicator looks for changes to the built-in group "Pre-Windows 2000 Compatible Access". This group grants read-only access to Active Directory. For more information see the following <a href="https://www.semperis.com/blog/security-risks-pre-windows-2000-compatibility-windows-2022/" target="_blank">Semperis blog entry.</a>'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'As part of a layered approach to security and to ensure that non-authenticated users cannot read Active Directory, it''s best to ensure this group does not contain the "Anonymous Logon" or "Everyone" groups.'
    ResultMessage = 'Found {0} changes to Pre-Windows 2000 Compatible Access group.'
    Remediation = 'Confirm that any addition or removals from Pre-Windows 2000 Compatible Access group are valid and properly accounted for.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Member'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Operation'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $results = Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -Server $DomainName -Recursive | 
               ForEach-Object { 
                   [PSCustomObject]@{
                       GroupDistinguishedName = "CN=Pre-Windows 2000 Compatible Access,CN=Users,$((Get-ADDomain $DomainName).DistinguishedName)"
                       Member = $_.SamAccountName
                       Operation = "Checked Membership"
                       EventTimestamp = (Get-Date)
                   }
               }

    foreach ($result in $results) {
        if ($result.Member -in @("Everyone", "ANONYMOUS LOGON")) {
            $result.Operation = "Risky Member Detected"
        }
        [void]$outputObjects.Add($result)
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
            ResultMessage = "No changes found in the Pre-Windows 2000 Compatible Access group."
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
