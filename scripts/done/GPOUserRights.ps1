[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 302
    UUID = '30a7fbd4-8ea3-42b2-b29d-41d27023c06a'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000302'
    Name = 'Dangerous user rights granted by GPO'
    ScriptName = 'GPOUserRights'
    Description = 'Group Policy Objects (GPOs) are used to define security settings that apply to a group of users or computers in an Active Directory environment. GPOs can be used to grant dangerous user rights, such as the ability to bypass file system security, log on as a service, or even perform actions with elevated privileges. This indicator looks for non-privileged users who are granted elevated permissions through GPO.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'An attacker can potentially exploit the user rights granted by a GPO to gain access to systems, steal sensitive information, or cause other types of damage. If these dangerous user rights are granted to a user or a group of users, it increases the risk of an attacker being able to gain access to sensitive data, systems or even perform malicious actions.'
    ResultMessage = 'Found {0} non-privileged users with elevated permissions granted using GPO.'
    Remediation = 'The remediation for this indicator involves identifying any dangerous user rights that have been granted through GPOs, and removing them wherever possible. This can involve reviewing existing GPO settings and modifying them to remove any unnecessary or excessive user rights, as well as implementing appropriate access controls to restrict access to GPOs and other critical Active Directory components. By taking these steps, organizations can reduce the risk of compromise and help protect their systems from potential attacks. For more information about user rights see <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment">MS User Rights Assignment</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'LinkedOUs'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Policy'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PolicyName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Privilege'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Status'; Type = 'String'; IsCollection = $false },
        @{ Name = 'User'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Local Account Monitoring', 'Harden - Strong Password Policy') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '2.5'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


try {
    $domainSID = (Get-ADDomain $DomainName).DomainSID

    $trustedSids = @(
        "S-1-3-0", "S-1-3-1", "S-1-3-4", "S-1-5-9", "S-1-5-18", "S-1-5-19", "S-1-5-20",
        "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", 
        "S-1-5-32-551", "S-1-5-32-552", "S-1-16-12288", "S-1-16-16384", 
        "S-1-16-20480", "S-1-16-28672", "S-1-5-32-557", "S-1-5-32-562", 
        "S-1-5-32-577", "S-1-5-32-578", "S-1-5-32-580", "S-1-5-32-545", "S-1-5-32-554",    
        "$domainSID-500", # Domain Administrator
        "$domainSID-502", # KRBTGT
        "$domainSID-512", # Domain Admins
        "$domainSID-515", # Domain Computers
        "$domainSID-516", # Domain Controllers
        "$domainSID-518", # Schema Admins (root domain)
        "$domainSID-519", # Enterprise Admins (root domain)
        "$domainSID-521", # Read-Only Domain Controllers
        "$domainSID-498", # Enterprise Read-Only Domain Controllers
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-9"         # Enterprise Domain Controllers
    )


    $outputObjects = [System.Collections.ArrayList]@()
    $gpoBasePath = "\\$DomainName\sysvol\$DomainName\Policies"
    $gpoFolders = Get-ChildItem -Path $gpoBasePath -Directory
    
    foreach ($folder in $gpoFolders) {
        $policyFile = Get-ChildItem -Path "$($folder.FullName)\Machine\Microsoft\Windows NT\SecEdit" -Filter "GptTmpl.inf" -Recurse
        if ($policyFile) {
            $content = Get-Content $policyFile.FullName
            foreach ($line in $content) {
                if ($line -match 'Se(.*)Privilege = (.+)') {
                    $privilege = $matches[1]
                    $users = $matches[2] -split ','
                    foreach ($user in $users) {
                        # Compare only the part after '*' in the SID
                        $sid = $user.TrimStart('*')
                        if ($trustedSids -notcontains $sid) {
                            $username = try { 
                                (Get-ADUser -Filter {SID -eq $sid}).SamAccountName 
                            } catch {
                                (Get-ADGroup -Filter {SID -eq $sid}).SamAccountName
                            }

                            $thisOutput = [PSCustomObject]@{
                                User      = $username
                                UserSID   = $sid
                                Privilege = $privilege
                                Policy    = $folder.Name
                            }
                            [void]$outputObjects.Add($thisOutput)
                        }
                    }
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status        = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation   = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = 'No non-privileged users found with elevated permissions.'
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}
return $res