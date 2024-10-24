# This script checks each domain to determine if DCShadow has been detected on any machines in the domain

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 13
    UUID = 'fa5662bf-8e17-42c3-a998-3d252f73b505'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000013'
    Name = 'Evidence of Mimikatz DCShadow attack'
    ScriptName = 'DCShadowInUse'
    Description = '<p>This indicator checks for certain evidence of a DCShadow attack performed using Mimikatz.</p>'
    Weight = 10
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 10
    LikelihoodOfCompromise = '<p>DCShadow attacks allow attackers that have achieved privileged domain access to inject arbitrary changes into AD by replicating from a &quot;fake&quot; domain controller. These changes bypass the security event log and can''t be spotted using standard monitoring tools.</p><br /><p>Mimikatz is a widely used tool used by both legitimate pen-testers as well as attackers. An attacker will use a DCShadow attack to establish persistence in Active Directory, creating backdoors to retain access even if the original privileged access compromise is resolved</p><h3>References</h3><p><a href="https://www.semperis.com/blog/why-most-organizations-still-cant-defend-against-dcshadow/" target="_blank">Why Most Organizations Still Can''t Defend against DCShadow - Semperis</a></p>'
    ResultMessage = 'Found {0} objects that indicate DCShadow may have been used to compromise your environment.'
    Remediation = '<p>If Active Directory is currently being penetration tested, it should be <b>immediately</b> verified with the team performing the testing that they have attempted a DCShadow attack against Active Directory.</p><br /><p>If it has been detected that there are traces of a DCShadow attack, the organization should <b>immediately</b> take action to determine if Active Directory has been compromised.</p><br /><p>Active Directory audit logs should be reviewed to determine the source of the attack, and the offending user or workstation should be taken offline or disabled to prevent further compromise. Further investigation may be required by an incident response team to determine if and what persistence has been implemented in Active Directory.</p><h3>References</h3><p><a href="https://www.semperis.com/blog/why-most-organizations-still-cant-defend-against-dcshadow/" target="_blank">Why Most Organizations Still Can''t Defend against DCShadow - Semperis</a></p><br /><p><a href="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management" target="_blank">Audit User Account Management - Windows 10 | Microsoft Learn</a></p>'
    Types = @('IoC')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Created'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'ManagedBy'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Isolate - Execution Isolation', 'Detect - Domain Account Monitoring') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = @()

try {
    $DN = (Get-ADDomain $DomainName).DistinguishedName
    $computers = Get-ADComputer -SearchBase $DN -Filter * -Properties whenCreated, managedBy, servicePrincipalName

    $filteredResults = $computers | Where-Object {
        $_.servicePrincipalName -like 'E3514235-4B06-11D1-AB04-00C04FC2DCD2*' -and 
        -not $_.rIDSetReferences
    }

    if ($filteredResults) {
        foreach ($result in $filteredResults) {
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $result.DistinguishedName
                Created           = if ($result.whenCreated) {
                    try {
                        [datetime]::ParseExact($result.whenCreated.ToString(), "yyyyMMddHHmmss.0Z", $null)
                    } catch {
                        $null
                    }
                } else {
                    $null
                }
                ManagedBy  = $result.managedBy
            }
            $outputObjects += $thisOutput
        }
        
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects found indicating DCShadow usage."
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
