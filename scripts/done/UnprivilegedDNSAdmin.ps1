[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [string]$DomainName
)

$Global:self = @{
    ID = 24
    UUID = 'e79191aa-b68f-4983-8420-b2ca25bca6ea'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000024'
    Name = 'Unprivileged principals as DNS Admins'
    ScriptName = 'UnprivilegedDNSAdmin'
    Description = 'This indicator looks for any member of the DnsAdmins group that is not a privileged user. DnsAdmins itself is not considered a privileged group and is not protected by the AdminSDHolder SDProp mechanism. However as some research has shown, a member of this group can remotely load a DLL onto a domain controller running DNS and execute code as SYSTEM.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Administration of DNS is often delegated to non-AD administrators (i.e., administrators with job responsibilities in networking, DNS, DHCP, etc.). These administration accounts may not have the same security controls as the AD administrator accounts, making them prime targets for compromise. For more information on how DNS admins can abuse privileges <a href="https://www.semperis.com/blog/dnsadmins-revisited/" target="_blank">see this blog post.</a>'
    ResultMessage = 'Found {0} objects which are not privileged but are members of the DNS Admins group.'
    Remediation = 'Remove unprivileged principals that are a member of the DNS Admins group.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Execution', 'Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_msdns', 'vuln1_dnsadmins') }
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
$failedObjects = @()

try {
    $domainDN = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $admins = Get-ADUser -Filter { adminCount -eq 1 } -SearchBase $domainDN -Properties objectSID

    $adminsSID = $admins | ForEach-Object { 
        New-Object System.Security.Principal.SecurityIdentifier $_.objectSID 
    }

    $dnsAdminsGroup = Get-ADGroup -Filter { SamAccountName -eq 'DnsAdmins' } -Properties DistinguishedName
    $dnsAdmins = Get-ADGroupMember -Identity $dnsAdminsGroup.DistinguishedName -Recursive

    foreach ($dnsAdmin in $dnsAdmins) {
        try {
            $dnsAdminSID = (Get-ADUser -Identity $dnsAdmin.SamAccountName -Properties objectSID).objectSID
            $SIDobject = New-Object System.Security.Principal.SecurityIdentifier $dnsAdminSID
            if ($SIDobject -notin $adminsSID) {
                $outputObjects += [PSCustomObject]@{
                    DomainName = $DomainName
                    DistinguishedName = $dnsAdmin.DistinguishedName
                    SamAccountName = $dnsAdmin.SamAccountName
                }
            }
        } catch {
            $failedObjects += $dnsAdmin.SamAccountName
        }
    }

    if ($outputObjects) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No unprivileged principals found in the DNS Admins group."
        }
    }

    if ($failedObjects) {
        $res.ResultMessage += " The following objects could not be read due to ACL restrictions: $($failedObjects -join '; ')."
        $res.Status = 'Error'
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
