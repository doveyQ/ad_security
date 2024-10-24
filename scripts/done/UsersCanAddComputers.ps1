[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)
$Global:self = @{
    ID = 11
    UUID = '6317479a-c7df-49ca-bbf1-47ecdf199792'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000011'
    Name = 'Unprivileged users can add computer accounts to the domain'
    ScriptName = 'UsersCanAddComputers'
    Description = 'This indicator checks for an AD configuration that allows unprivileged domain members to add computer accounts to the domain. By default, members of the Authenticated Users group can add up to 10 machine accounts to a domain. If the ms-DS-MachineAccountQuota attribute on the domain naming context head is not set to 0, regular users have this ability.The ability to do this confers certain rights on those created machine accounts that can be abused by a variety of Kerberos-based attacks. Note: This configuration may be enabled but be already mitigated by GPO settings (User Right: "Add workstations to domain" configured with only high-privileged group(s)/account(s)) linked to Domain Controllers OU that are not checked by this indicator.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'The ability to add computer accounts to a domain without restrictions or monitoring present opportunities for attackers to add their own accounts or take advantage of uncontrolled computers with vulnerabilities, thereby extending their reach and entrenching themselves in the environment.'
    ResultMessage = 'Found {0} domains in which regular users can add computer accounts.'
    Remediation = 'Set the ms-DS-MachineAccountQuota attribute on the domain NC head to 0 to disable regular users'' ability to add computer accounts.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'MachineAccountQuota'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Lateral Movement') }
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

    $domainParts = $DomainName -split '\.'
    $OU = ($domainParts | ForEach-Object { "DC=$_" }) -join ','

    $delegatedUsers = (Get-Acl -Path "AD:$OU").Access | Where-Object {
        $_.ActiveDirectoryRights -match "CreateChild" -and $_.ObjectType -eq ([Guid]"bf967a86-0de6-11d0-a285-00aa003049e2")
    }

    if ($delegatedUsers) {
        foreach ($user in $delegatedUsers) {
            $outputObjects += [PSCustomObject]@{
                IdentityReference = $user.IdentityReference
                Rights = $user.ActiveDirectoryRights
                ObjectType = $user.ObjectType
            }
        }

        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
            
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No users found with the ability to add computers to the domain."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ErrorMessage = $_.Exception.Message
    }
}

return $res