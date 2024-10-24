[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 217
    UUID = '9e2e34e4-a367-40a7-b8ea-f4b32e99d74f'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000217'
    Name = 'Query policies that have the attribute of ldap deny list set.'
    ScriptName = 'LdapDenyList'
    Description = 'This security indicator is designed to check for LDAP IP deny lists across multiple domains in an Active Directory environment. For each available domain, it query the Active Directory for "query policies" associated with that domain, specifically looking for LDAP IP deny lists (ldapipdenylist attribute).'
    Weight = 5
    Severity = 'Informational'
    Schedule = '7d'
    Impact = 5
    LikelihoodOfCompromise = 'Unauthorized or unexpected entries in the LDAP IP deny list could suggest a security breach or an attempt to limit access to critical resources maliciously. The likelihood of compromise depends on the following factors:<ol><li>Unexpected Changes: Unauthorized modifications to the LDAP IP deny list.</li><li>Unknown IP Addresses: Presence of IP addresses that are not recognized or authorized by the network administration team.</li><li>Security Policy Violations: Entries that violate the organization''s established security policies.</li></ol>'
    ResultMessage = 'Found {0} query policies with ldap deny list set.'
    Remediation = 'To mitigate potential security risks associated with the LDAP IP deny list, the following steps are recommended:<ol><li>Regular Audits: Conduct regular reviews of the LDAP IP deny list to ensure all entries are authorized and legitimate.</li><li>Change Management: Implement strict change management procedures for modifications to the LDAP IP deny list. (Semperis DSP for example).</li><li>Security Policy Violations: Entries that violate the organization''s established security policies.</li><li>Security Monitoring: Utilize security information and event management (SIEM) tools to monitor for unauthorized changes or access attempts blocked by the deny list.</li></ol>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LdapDenyList'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Impact') }
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
    $outputObjects = @()

    $DN = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $searchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DN"
    
    $queryPolicies = Get-ADObject -SearchBase $searchBase -Filter { objectClass -eq 'queryPolicy' } -Property ldapipdenylist, DistinguishedName, whenChanged

    foreach ($policy in $queryPolicies) {
        if ($policy.ldapipdenylist) {
            $denyListBytes = $policy.ldapipdenylist
            $lastEdited = $policy.whenChanged
            $denyListHex = -join ($denyListBytes | ForEach-Object { "{0:X2}" -f $_ })
            $outputObjects += [PSCustomObject] @{
                DistinguishedName = $policy.DistinguishedName
                DomainName = $DomainName
                LdapDenyList = $denyListHex
                LastEdited = $lastEdited
            }
        }
    }

    if ($outputObjects.Count -gt 0){
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status ='Failed'
            ResultMessage = "No query policies with LDAP deny list found." 
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
