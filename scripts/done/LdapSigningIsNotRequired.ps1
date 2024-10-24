[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 153
    UUID = '4fe825ed-07fb-4b06-913a-be5c9542ca54'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000153'
    Name = 'LDAP signing is not required on Domain Controllers'
    ScriptName = 'LdapSigningIsNotRequired'
    Description = '<p>This indicator checks for domain controllers where LDAP signing is not required.</p>'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Unsigned network traffic is exposed to MiTM attacks, where attackers alter packets and forward them to the LDAP server, causing the server to make decisions based on forged requests from the LDAP client.'
    ResultMessage = 'Found {0} DCs that do not require LDAP Signing.'
    Remediation = '<p>To remediate follow the steps below.</p><br /><p><b>If the steps are not followed in order, disruption to Active Directory may occur.</b></p><br /><p>Configure clients to request LDAP signing. Group policy: <b>Network security:LDAP client signing requirements</b>, select <b>Negotiate signing</b>.</p><br /><p>When all clients request signing, configure domain controllers to require LDAP signing. Group policy: <b>Domain controller:LDAP server signing requirements</b>, select <b>Require signing</b>.</p><br /><p>Configure clients to require LDAP signing. Group policy: <b>Network security:LDAP client signing requirements</b>, select <b>Require signing</b>.</p><br /><p>For full details on the process please see the reference articles.</p><h3>References</h3><p><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements" target="_blank">Domain controller LDAP server signing requirements - Windows 10 | Microsoft Learn</a></p><br /><p><a href="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements" target="_blank">Network security LDAP client signing requirements - Windows 10 | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'HostName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'State'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Credential Access') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


# if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
#     Install-WindowsFeature RSAT-AD-PowerShell
# }


$outputObjects = [System.Collections.ArrayList]@()
$domainControllers = Get-ADDomainController -Filter * | Select-Object Name, HostName, Site

try {
    function Get-LDAPSigningFromRegistry {
        param (
            [Parameter(Mandatory=$true)]
            $DCName
        )

        try {
            $ldapSetting = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name LDAPServerIntegrity -ErrorAction Stop
            
            if ($null -eq $ldapSetting.LDAPServerIntegrity) {
                return "Not Configured"
            }

            switch ($ldapSetting.LDAPServerIntegrity) {
                0 { return "Disabled" }
                1 { return "Enabled" }
                2 { return "Required" }
                Default { return "Unknown" }
            }
        } catch {
            return "Error retrieving registry setting"
        }
    }

    function Get-LDAPSigningFromGPO {
        param (
            [Parameter(Mandatory=$true)]
            $DomainController
        )

        $gpoReport = Get-GPOReport -Name "Default Domain Policy" -ReportType Xml
        $xml = [xml]$gpoReport
        $namespaceManager = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $namespaceManager.AddNamespace("q1", "http://www.microsoft.com/GroupPolicy/PolicyDefinitions")

        $settingNode = $xml.DocumentElement.SelectSingleNode("//q1:DisplayString", $namespaceManager)

        switch ($settingNode.InnerText) {
            "Signatur erforderlich" { return "LDAP Signing is Required" }
            "Keine Signatur erforderlich" { return "LDAP Signing is Not Required" }
            Default { return "Unknown GPO Setting" }
        }
    }


    foreach ($dc in $domainControllers) {
        Write-Host "Checking LDAP Signing Requirements for Domain Controller: $($dc.Name)"
        
        $registrySetting = Get-LDAPSigningFromRegistry -DCName $dc.Name
        
        $groupPolicySetting = Get-LDAPSigningFromGPO -DomainController $dc.Name

        $object = [PSCustomObject][Ordered] @{
            HostName = $dc.HostName
        }
        [void]$outputObjects.Add($object)
        
        if ($registrySetting -eq "Required" -or $groupPolicySetting -eq "LDAP Signing is Required") {
            $res = [PSCustomObject][Ordered]@{
                Status = "Passed"
                ResultObjects = $outputObjects
                ResultMessage = "LDAP Signing is Required"
            }
        } elseif ($groupPolicySetting -ne "Not Configured in GPO") {
            $res = [PSCustomObject][Ordered]@{
                Status = "Passed"
                ResultObjects = $outputObjects
                ResultMessage = "LDAP Signing is Required (via GPO)"
            }
        } else {
            $res = [PSCustomObject]@{
                Status         = "Failed"
                ResultMessage  = $self.ResultMessage -f $outputObjects.Count
                ResultObjects  = $outputObjects
                Remediation    = $self.Remediation
            }
        }
    }
}
catch {
    $res = [PSCustomObject][Ordered]@{
        Status  = "Error"
        Message = "An error occurred: $_"
    }
}

return $res