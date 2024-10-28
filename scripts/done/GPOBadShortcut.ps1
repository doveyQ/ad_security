[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 189
    UUID = 'cfe6f680-8137-4690-8116-80aa3d4b9d52'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000189'
    Name = 'Writable shortcuts found in GPO'
    ScriptName = 'GPOBadShortcut'
    Description = 'This indicator looks for writable shortcuts in Group Policy Objects (GPOs) that could be modified by low-privilege users.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'Writable shortcuts in GPOs can be abused by attackers to gain unauthorized access or persist in a compromised system.'
    ResultMessage = 'Found {0} writable shortcuts in GPOs that could be modified by low-privilege users.'
    Remediation = 'Review and adjust permissions on identified writable shortcuts to ensure only authorized users have access.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'FilePath'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ShortCutPath'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ShortCutName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Policy'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PolicyName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Credential Access') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $domainSID = (Get-ADDomain -Server $DomainName).DomainSID.Value

    $trustedSids = @(
        "S-1-3-0", "S-1-3-1", "S-1-3-4", "S-1-5-9", "S-1-5-18", "S-1-5-19", "S-1-5-20",
        "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", 
        "S-1-5-32-551", "S-1-5-32-552", "S-1-16-12288", "S-1-16-16384", 
        "S-1-16-20480", "S-1-16-28672", "S-1-5-32-557", "S-1-5-32-562", 
        "S-1-5-32-577", "S-1-5-32-578", "S-1-5-32-580", "S-1-5-32-545",         
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
    
    $aclsToCheck = @("CreateFiles", "AppendData", "DeleteSubdirectoriesAndFiles", "Delete", "ChangePermissions", "TakeOwnership", "FullControl", "Write", "Modify")
    $filesToSearch = @("Shortcuts.xml")

    $domainDN = (Get-ADDomain -Server $DomainName).DistinguishedName
    $policies = Get-ADObject -Filter { objectClass -eq 'groupPolicyContainer' } -SearchBase "CN=Policies,CN=System,$domainDN" -Property cn, displayName, gPCFileSysPath

    foreach ($policy in $policies) {
        $policyFiles = Get-ChildItem -Path $policy.gPCFileSysPath -Recurse -Include $filesToSearch -Force
        foreach ($file in $policyFiles) {
            $xml = [xml](Get-Content -Path $file.FullName)
            foreach ($shortcut in $xml.Shortcuts.Shortcut) {
                $name = $shortcut.Name
                $targetPath = $shortcut.Properties.TargetPath
                $shortcutPath = $shortcut.Properties.ShortcutPath

                $fileACL = Get-ACL $targetPath -ErrorAction SilentlyContinue
                if ($fileACL) {
                    $usersWithPrivileges = [System.Collections.ArrayList]@()
                    foreach ($acl in $fileACL.Access) {
                        $sid = try {
                            (New-Object System.Security.Principal.NTAccount($acl.IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch {
                            $acl.IdentityReference.ToString()
                        }

                        if (-not $trustedSids.Contains($sid)) {
                            foreach ($right in $aclsToCheck) {
                                if ($acl.FileSystemRights.ToString() -match $right) {
                                    [void]$usersWithPrivileges.Add($acl.IdentityReference)
                                    break
                                }
                            }
                        }
                    }

                    if ($usersWithPrivileges.Count -gt 0) {
                        $outputObjects.Add([PSCustomObject][Ordered]@{
                            FilePath            = $targetPath
                            ShortCutPath        = $shortcutPath
                            ShortCutName        = $name
                            UsersWithPrivileges = $usersWithPrivileges -join ";"
                            Policy              = $policy.cn
                            PolicyName          = $policy.displayName
                        })
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
            ResultMessage = "No writable shortcuts found."
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
