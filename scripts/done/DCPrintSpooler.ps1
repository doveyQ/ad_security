﻿# This script looks for DCs that have the print spooler service running

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 77
    UUID = '33ed032b-3cab-4105-b4f6-5477cb3c9aa1'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000077'
    Name = 'Print spooler service is enabled on a DC'
    ScriptName = 'DCPrintSpooler'
    Description = '<p>This indicator checks for Domain Controllers running the print spooler service.</p><br /><p>This indicator <b>requires</b> the local server to be running the print spooler service to function, or it will return <b>Failed to run</b>.</p>'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = '<p>The Windows print spooler service is vulnerable to remote code execution if unpatched, commonly referred to as <b>PrintNightmare</b>. These vulnerabilities are documented in CVE-2021-34527 and CVE-2021-1675.</p><br /><p>The print spooler service can also be used by an attacker in combination with unconstrained Kerberos delegation and TGT delegation enabled across trusts.</p><h3>References</h3><p><a href="https://www.semperis.com/blog/what-you-need-to-know-about-printnightmare-the-critical-windows-print-spooler-vulnerability/" target="_blank">What You Need to Know about PrintNightmare, the Critical Windows Print Spooler Vulnerability - Semperis</a></p><br /><p><a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527" target="_blank">CVE-2021-34527 - Security Update Guide - Microsoft - Windows Print Spooler Remote Code Execution Vulnerability</a></p><br /><p><a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675" target="_blank">CVE-2021-1675 - Security Update Guide - Microsoft - Windows Print Spooler Remote Code Execution Vulnerability</a></p><br /><p><a href="https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-0683" target="_blank">CVE-2019-0683 - Security Update Guide - Microsoft - Active Directory Elevation of Privilege Vulnerability</a></p>'
    ResultMessage = 'Found {0} DCs that have the Print Spooler service running.'
    Remediation = '<p>Organizations should disable the print spooler service on domain controllers. The print spooler service has a long history of abuse by attackers, with the most recent being <b>PrintNightmare</b>.</p><br /><p>If organizations are publishing printers to Active Directory, they should evaluate disabling print spooler on domain controllers and performing a manual process to instead prune printers.</p><h3>References</h3><p><a href="https://www.semperis.com/blog/what-you-need-to-know-about-printnightmare-the-critical-windows-print-spooler-vulnerability/" target="_blank">What You Need to Know about PrintNightmare, the Critical Windows Print Spooler Vulnerability - Semperis</a></p><br /><p><a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527" target="_blank">CVE-2021-34527 - Security Update Guide - Microsoft - Windows Print Spooler Remote Code Execution Vulnerability</a></p><br /><p><a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675" target="_blank">CVE-2021-1675 - Security Update Guide - Microsoft - Windows Print Spooler Remote Code Execution Vulnerability</a></p><br /><p><a href="https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-0683" target="_blank">CVE-2019-0683 - Security Update Guide - Microsoft - Active Directory Elevation of Privilege Vulnerability</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'HostName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Execution', 'Lateral Movement', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Software Update') }
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
    $dclist = Get-ADDomainController -Filter *

    foreach ($dc in $dclist){
        $service = Get-Service -Name Spooler -ComputerName $dc.Name -ErrorAction SilentlyContinue
        if ($service.Status -eq 'Running') {
            $outputObjects += [PSCustomObject]@{
                ComputerObjectDN = $dc.ComputerObjectDN
                ServiceStatus     = $service.Status
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
            ResultMessage = "No Domain Controllers found with the Print Spooler service running."
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
