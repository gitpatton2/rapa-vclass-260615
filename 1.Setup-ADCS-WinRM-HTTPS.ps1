#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    All-in-one script that installs AD CS (Enterprise Root CA), creates a machine
    certificate auto-enrollment template, deploys GPO (autoenrollment / firewall /
    listener), and configures the DC's own WinRM-HTTPS listener.

.DESCRIPTION
    Run on : a Domain Controller with AD DS installed, from an elevated (Administrator)
             PowerShell session.
    Running this once on the DC will:
      1) Install the AD CS role and configure an Enterprise Root CA
      2) Clone the built-in "Machine (Computer)" template into a V2 autoenrollment
         template (includes the Server Authentication EKU -> usable for WinRM HTTPS)
      3) Grant Read + Enroll + AutoEnroll to Domain Computers / Domain Controllers
         and publish the template on the CA
      4) Create and link a GPO:
            - Certificate autoenrollment policy (AEPolicy=7)
            - Firewall inbound rule for 5986 (PolicyStore method, actually works)
            - Startup script (Scripts CSE correctly registered in
              gPCMachineExtensionNames)
         -> every domain computer obtains a cert and configures its HTTPS listener
            automatically on reboot / gpupdate
      5) Issue a certificate to the DC itself and configure HTTPS listener + local
         firewall immediately
      6) Run full validation and print Ansible (psrp) connection guidance

.NOTES
    Idempotent: safe to run multiple times.
#>

[CmdletBinding()]
param(
    [string]$CACommonName        = 'vclass-Root-CA',
    [string]$TemplateName        = 'WinRM-HTTPS-Automation',   # template cn (the name the CA references)
    [string]$TemplateDisplayName = 'WinRM HTTPS Automation',
    [string]$GpoName             = 'WinRM_HTTPS_Security_Policy',
    [int]   $WinRMHttpsPort      = 5986,
    [int]   $CertWaitSeconds     = 180
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------------------------
function Write-Step { param($m) Write-Host "`n[STEP] $m" -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Skip { param($m) Write-Host "  [SKIP] $m" -ForegroundColor DarkGray }
function Write-Info { param($m) Write-Host "  [INFO] $m" -ForegroundColor DarkGray }
function Write-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red; throw $m }

$LogDir = Join-Path $env:ProgramData 'WinRMHTTPS'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
try { Start-Transcript -Path (Join-Path $LogDir ("setup-{0}.log" -f (Get-Date -Format yyyyMMdd-HHmmss))) -Force | Out-Null } catch {}

Import-Module ServerManager     -ErrorAction SilentlyContinue
Import-Module ActiveDirectory   -ErrorAction Stop
Import-Module GroupPolicy       -ErrorAction Stop

$DomainDN   = (Get-ADDomain).DistinguishedName
$DomainFQDN = (Get-ADDomain).DNSRoot
$ForestDN   = (Get-ADRootDSE).rootDomainNamingContext
$ConfigPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$ForestDN"
$ServerAuthOid = '1.3.6.1.5.5.7.3.1'
$FwRuleName = "Ansible WinRM HTTPS (TCP $WinRMHttpsPort)"

# ============================================================================
# Shared functions
# ============================================================================
function Get-CertSvcConfigName {
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    if (Test-Path $p) {
        $i = Get-ChildItem -Path $p -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($i) { return $i.PSChildName }
    }
    return $null
}

function Ensure-CertSvcRunning {
    $svc = Get-Service -Name certsvc -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') { Set-Service -Name certsvc -StartupType Automatic }
    if ($svc.Status -ne 'Running')      { Start-Service -Name certsvc; $svc.WaitForStatus('Running','00:00:60') }
}

# Detect whether a system restart is pending (common after the AD CS role install).
function Test-PendingReboot {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
    $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($sm -and $sm.PendingFileRenameOperations) { return $true }
    return $false
}

# Make sure the ADCSDeployment module (provides Install-AdcsCertificationAuthority)
# is available and loaded in the current session.
function Ensure-AdcsModule {
    if (Get-Module -ListAvailable -Name ADCSDeployment) {
        Import-Module ADCSDeployment -ErrorAction Stop
        Write-OK 'ADCSDeployment module loaded'
        return
    }

    # The module ships with the AD CS role management tools. If it is missing,
    # (re)install the management tools, then refresh the module path for this session.
    Write-Info 'ADCSDeployment module not found; installing AD CS management tools...'
    Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
    Install-WindowsFeature -Name RSAT-ADCS,RSAT-ADCS-Mgmt -ErrorAction SilentlyContinue | Out-Null
    $env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath','Machine')

    if (Get-Module -ListAvailable -Name ADCSDeployment) {
        Import-Module ADCSDeployment -ErrorAction Stop
        Write-OK 'ADCSDeployment module loaded (after installing management tools)'
        return
    }

    # Still missing -> almost always a pending reboot from the initial role install.
    if (Test-PendingReboot) {
        Write-Fail 'A RESTART is required to finish the AD CS role installation. Please REBOOT this server, then run this script again (it is idempotent and resumes automatically).'
    } else {
        Write-Fail 'ADCSDeployment module could not be located even after installing management tools. Open a NEW elevated PowerShell window and run the script again; if it still fails, reboot the server.'
    }
}

function Get-ServerAuthCert {
    param([string]$CaCn)
    $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
    $candidates = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date) -and
        ($_.Issuer -match [regex]::Escape($CaCn)) -and
        (@($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }) -contains $ServerAuthOid)
    }
    if (-not $candidates) { return $null }
    # Prefer a cert that explicitly carries the host FQDN in its Subject CN or DNS SAN
    # (our WinRM template), then by latest expiry. This avoids the subject-less DC cert.
    $candidates |
        Sort-Object `
            @{ Expression = {
                $cn  = ($_.Subject  -match ("CN=" + [regex]::Escape($fqdn)))
                $san = (@($_.DnsNameList | ForEach-Object { $_.Unicode }) -contains $fqdn)
                if ($cn) { 0 } elseif ($san) { 1 } else { 2 }
            }; Ascending = $true },
            @{ Expression = 'NotAfter'; Descending = $true } |
        Select-Object -First 1
}

function Wait-ForPath {
    param([string]$Path,[int]$MaxSeconds=120,[int]$Interval=5)
    for ($i=0; $i -lt [Math]::Ceiling($MaxSeconds/$Interval); $i++) {
        if (Test-Path $Path) { return $true }
        Start-Sleep -Seconds $Interval
    }
    return $false
}

# Clone the built-in Machine (Computer) template into a V2 autoenrollment template
function New-WinRMTemplate {
    param($ConfigPath,$TemplateName,$TemplateDisplayName)

    $dn = "CN=$TemplateName,$ConfigPath"
    if ([ADSI]::Exists("LDAP://$dn")) {
        Write-Skip "Template '$TemplateName' already exists."
        return (Get-ADObject -Identity $dn)
    }

    $src = [ADSI]"LDAP://CN=Machine,$ConfigPath"   # built-in Computer template (Server/Client Auth EKU, subject = AD DNS name)
    if (-not $src.Path) { Write-Fail "Source template 'CN=Machine' not found." }

    $container = [ADSI]"LDAP://$ConfigPath"
    $new = $container.Children.Add("CN=$TemplateName", "pKICertificateTemplate")

    # Attributes copied verbatim from the source (incl. binary/multi-valued -> use ADSI .Value to preserve types)
    $copy = @(
        'flags','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
        'pKICriticalExtensions','pKIExtendedKeyUsage','pKIExpirationPeriod','pKIOverlapPeriod',
        'pKIDefaultCSPs','msPKI-RA-Signature','msPKI-Private-Key-Flag',
        'msPKI-Certificate-Name-Flag','msPKI-Minimal-Key-Size','msPKI-Certificate-Application-Policy'
    )
    foreach ($a in $copy) {
        $v = $src.Properties[$a].Value
        if ($null -ne $v) { $new.Properties[$a].Value = $v }
    }

    # Promote to V2 template + unique OID + autoenrollment flag
    $oid = '1.3.6.1.4.1.311.21.8.' + (Get-Random -Minimum 100000 -Maximum 999999) + '.' +
           (Get-Random -Minimum 100000 -Maximum 999999) + '.' +
           (Get-Random -Minimum 1000   -Maximum 9999)   + '.' +
           (Get-Random -Minimum 1000   -Maximum 9999)
    $new.Properties['displayName'].Value                   = $TemplateDisplayName
    $new.Properties['revision'].Value                      = 100
    $new.Properties['msPKI-Template-Schema-Version'].Value = 2
    $new.Properties['msPKI-Template-Minor-Revision'].Value = 0
    $new.Properties['msPKI-Cert-Template-OID'].Value       = $oid
    # 0x20 = CT_FLAG_AUTO_ENROLLMENT (participate in autoenrollment). PEND_ALL_REQUESTS(0x2) is NOT set -> auto issue.
    $new.Properties['msPKI-Enrollment-Flag'].Value         = 0x20
    $new.CommitChanges()

    Write-OK "Template '$TemplateName' created (cloned from Machine, V2, OID=$oid)."
    return (Get-ADObject -Identity $dn)
}

# Grant Read + Enroll + AutoEnroll on the template (idempotent)
function Grant-TemplateEnroll {
    param([string]$TemplateDN,[string[]]$GroupNames)

    $enroll = [guid]'0e100377-9875-11d1-89e6-00a02474429e'
    $auto   = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $entry  = [ADSI]"LDAP://$TemplateDN"
    $sd     = $entry.psbase.ObjectSecurity
    $rules  = $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])

    function Test-HasRule($rules,$sid,[string]$right,$objGuid) {
        foreach ($r in $rules) {
            if ($r.IdentityReference -eq $sid -and $r.AccessControlType -eq 'Allow') {
                if ($objGuid) {
                    if ($r.ObjectType -eq $objGuid -and ($r.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) { return $true }
                } else {
                    if ($r.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericRead) { return $true }
                }
            }
        }
        return $false
    }

    foreach ($g in $GroupNames) {
        $sid = (Get-ADGroup -Identity $g).SID
        if (-not (Test-HasRule $rules $sid 'Read' $null)) {
            $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,[System.DirectoryServices.ActiveDirectoryRights]'GenericRead',[System.Security.AccessControl.AccessControlType]'Allow')))
        }
        if (-not (Test-HasRule $rules $sid 'ER' $enroll)) {
            $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,[System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight',[System.Security.AccessControl.AccessControlType]'Allow',$enroll)))
        }
        if (-not (Test-HasRule $rules $sid 'ER' $auto)) {
            $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,[System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight',[System.Security.AccessControl.AccessControlType]'Allow',$auto)))
        }
        Write-OK "Granted: $g (Read/Enroll/AutoEnroll)"
    }
    $entry.psbase.CommitChanges()
}

# Register the computer-side CSE on the GPO (merge into gPCMachineExtensionNames)
# -- this is what makes the startup script actually get processed by clients.
function Add-GpoMachineCSE {
    param([guid]$GpoId,[string]$DomainDN,[string[]]$CseAndTools)

    $dn  = "CN={$GpoId},CN=Policies,CN=System,$DomainDN"
    $obj = Get-ADObject -Identity $dn -Properties gPCMachineExtensionNames
    $cur = $obj.gPCMachineExtensionNames

    $map = @{}
    if ($cur) {
        foreach ($g in [regex]::Matches($cur,'\[(.*?)\]')) {
            $guids = [regex]::Matches($g.Groups[1].Value,'\{[0-9A-Fa-f\-]+\}') | ForEach-Object { $_.Value.ToUpper() }
            if ($guids.Count -ge 1) {
                $cse = $guids[0]
                if (-not $map.ContainsKey($cse)) { $map[$cse] = New-Object 'System.Collections.Generic.List[string]' }
                foreach ($t in ($guids | Select-Object -Skip 1)) { if (-not $map[$cse].Contains($t)) { $map[$cse].Add($t) } }
            }
        }
    }
    $cse = $CseAndTools[0].ToUpper()
    if (-not $map.ContainsKey($cse)) { $map[$cse] = New-Object 'System.Collections.Generic.List[string]' }
    foreach ($t in ($CseAndTools | Select-Object -Skip 1)) {
        $tu = $t.ToUpper(); if (-not $map[$cse].Contains($tu)) { $map[$cse].Add($tu) }
    }

    $sb = ''
    foreach ($k in ($map.Keys | Sort-Object)) {
        $tools = ($map[$k] | Sort-Object) -join ''
        $sb += '[' + $k + $tools + ']'
    }
    Set-ADObject -Identity $dn -Replace @{ gPCMachineExtensionNames = $sb }
    Write-OK "gPCMachineExtensionNames updated: $sb"
}

# Update GPT.INI Version (preserving existing content)
function Set-GptIniVersion {
    param([string]$Path,[int]$Version,[string]$DisplayName)
    if (Test-Path $Path) {
        $lines = Get-Content -Path $Path
        $out = @(); $hasGeneral=$false; $setVer=$false
        foreach ($l in $lines) {
            if ($l -match '^\s*\[General\]') { $hasGeneral=$true; $out += $l; continue }
            if ($l -match '^\s*Version\s*=') { $out += "Version=$Version"; $setVer=$true; continue }
            $out += $l
        }
        if (-not $hasGeneral) { $out = @('[General]') + $out }
        if (-not $setVer) {
            $tmp=@(); foreach ($l in $out) { $tmp += $l; if ($l -match '^\s*\[General\]') { $tmp += "Version=$Version" } }
            $out = $tmp
        }
        Set-Content -Path $Path -Value $out -Encoding Ascii
    } else {
        Set-Content -Path $Path -Value @('[General]',"Version=$Version","displayName=$DisplayName") -Encoding Ascii
    }
}

# Bump GPO computer version +1 (keep AD versionNumber and GPT.INI in sync)
function Update-GpoComputerVersion {
    param([guid]$GpoId,[string]$DomainDN,[string]$GptIniPath,[string]$DisplayName)
    $dn  = "CN={$GpoId},CN=Policies,CN=System,$DomainDN"
    $obj = Get-ADObject -Identity $dn -Properties versionNumber
    [int]$v = if ($obj.versionNumber) { $obj.versionNumber } else { 0 }
    $user = $v -band 0xFFFF
    $comp = (($v -shr 16) + 1) -band 0xFFFF
    $newV = ($comp -shl 16) -bor $user
    Set-ADObject -Identity $dn -Replace @{ versionNumber = [int]$newV }
    Set-GptIniVersion -Path $GptIniPath -Version $newV -DisplayName $DisplayName
    Write-OK "GPO version synced: versionNumber=$newV (computer ver +1)"
}

# Robustly (re)create the WinRM HTTPS listener.
# "New-WSManInstance : An internal error occurred" is most often caused by a stale
# HTTP.sys SSL binding left on the port by an earlier attempt (possibly bound to a
# specific IP or hostname, so it is invisible to the WSMan listener enumeration), or by
# a broken private-key association on the certificate. We clear ALL bindings on the
# port, repair the key, then create -- with a netsh direct-bind fallback that surfaces
# the real error code.
function Remove-HttpSslBindingsOnPort {
    param([int]$Port)
    $show = & netsh http show sslcert 2>$null
    foreach ($line in $show) {
        if ($line -match '^\s*IP:port\s*:\s*(\S+)') {
            $b = $matches[1]
            if ($b -match ":$Port$") { & netsh http delete sslcert ipport=$b 2>&1 | Out-Null; Write-Info "Removed stale HTTP.sys binding ipport=$b" }
        }
        elseif ($line -match '^\s*Hostname:port\s*:\s*(\S+)') {
            $b = $matches[1]
            if ($b -match ":$Port$") { & netsh http delete sslcert hostnameport=$b 2>&1 | Out-Null; Write-Info "Removed stale HTTP.sys binding hostnameport=$b" }
        }
    }
}

function Test-HttpsListenerExists {
    $l = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue |
         Where-Object { $_.Transport -eq 'HTTPS' }
    return [bool]$l
}

function Set-WinRMHttpsListener {
    param([string]$Thumbprint,[string]$Fqdn,[int]$Port)

    # 1) Remove any existing WSMan HTTPS listener (both APIs, for completeness)
    Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue |
        Where-Object { $_.Transport -eq 'HTTPS' } |
        ForEach-Object { Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address=$_.Address; Transport='HTTPS'} -ErrorAction SilentlyContinue } |
        Out-Null
    Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
        Where-Object { ($_.Keys -join ';') -match 'Transport=HTTPS' } |
        ForEach-Object { Remove-Item -Path ("WSMan:\localhost\Listener\{0}" -f $_.Name) -Recurse -Force -ErrorAction SilentlyContinue } |
        Out-Null

    # 2) Clear ALL stale HTTP.sys SSL bindings on the port (any IP / hostname)
    Remove-HttpSslBindingsOnPort -Port $Port

    # 3) Repair the certificate's private-key association (a broken link also yields "internal error")
    & certutil -repairstore My $Thumbprint 2>&1 | Out-Null

    Restart-Service -Name WinRM -Force -ErrorAction SilentlyContinue

    # 4) Create the listener -- try the cmdlet, then the WSMan: provider
    try {
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address='*'; Transport='HTTPS'} `
            -ValueSet @{Hostname=$Fqdn; CertificateThumbprint=$Thumbprint} -ErrorAction Stop | Out-Null
        return $true
    } catch { Write-Warn "New-WSManInstance failed: $($_.Exception.Message)" }

    try {
        New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS `
            -Hostname $Fqdn -CertificateThumbPrint $Thumbprint -Force -ErrorAction Stop | Out-Null
        return $true
    } catch { Write-Warn "WSMan: provider failed: $($_.Exception.Message)" }

    # 5) Reliable path for subject-less / CNG-key certs: bind via netsh (HTTP.sys does no
    #    hostname validation and accepts CNG keys), then create the WinRM listener WITH AN
    #    EMPTY CertificateThumbprint so it SHARES that binding (WinRM requires empty in that case).
    Remove-HttpSslBindingsOnPort -Port $Port
    $appid = '{6FB5BB1B-0000-4F1A-9A0C-2E5D5F0E5A10}'
    $bindOut = & netsh http add sslcert ipport=0.0.0.0:$Port certhash=$Thumbprint appid=$appid certstorename=MY 2>&1
    Write-Info ("netsh add sslcert -> " + (($bindOut | Out-String).Trim()))
    $bound = ($LASTEXITCODE -eq 0) -or (($bindOut | Out-String) -match 'successfully')
    if ($bound) {
        # a) cmdlet with empty thumbprint
        try {
            New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address='*'; Transport='HTTPS'} `
                -ValueSet @{Hostname=$Fqdn; CertificateThumbprint=''} -ErrorAction Stop | Out-Null
        } catch { Write-Warn "Shared-binding listener (cmdlet) failed: $($_.Exception.Message)" }
        # b) WSMan: provider with empty thumbprint
        if (-not (Test-HttpsListenerExists)) {
            try {
                New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS `
                    -Hostname $Fqdn -CertificateThumbPrint '' -Force -ErrorAction Stop | Out-Null
            } catch { Write-Warn "Shared-binding listener (provider) failed: $($_.Exception.Message)" }
        }
        # c) winrm.cmd with empty thumbprint
        if (-not (Test-HttpsListenerExists)) {
            & cmd.exe /c "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$Fqdn`";CertificateThumbprint=`"`"}" 2>&1 | Out-Null
        }
        if (Test-HttpsListenerExists) {
            Write-OK 'HTTPS listener created (sharing the netsh SSL binding, empty thumbprint)'
            return $true
        }
    }
    return $false
}

# Configure this machine's (the DC's) own WinRM HTTPS listener
function Ensure-LocalWinRMHttps {
    param([string]$CaCn,[int]$Port,[string]$FwRuleName)

    # Ensure base WinRM configuration
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WinRM -ErrorAction SilentlyContinue
    try { Set-WSManQuickConfig -Force -SkipNetworkProfileCheck -ErrorAction Stop 2>&1 | Out-Null } catch { winrm quickconfig -quiet 2>&1 | Out-Null }


    $cert = Get-ServerAuthCert -CaCn $CaCn
    if (-not $cert) {
        Write-Info "No certificate yet -> triggering autoenrollment"
        gpupdate /target:computer /force 2>&1 | Out-Null
        certutil -pulse 2>&1 | Out-Null
        try { Get-Certificate -Template $TemplateName -CertStoreLocation Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Out-Null } catch {}
        for ($i=0; $i -lt [Math]::Ceiling($CertWaitSeconds/10); $i++) {
            Start-Sleep 10
            $cert = Get-ServerAuthCert -CaCn $CaCn
            if ($cert) { break }
            if (($i % 3) -eq 2) { certutil -pulse 2>&1 | Out-Null }
            Write-Info "Waiting for certificate... ($([int](($i+1)*10))/$CertWaitSeconds s)"
        }
    }
    if (-not $cert) { Write-Warn "Failed to obtain a DC certificate -- skipping listener configuration."; return $null }

    $dnsNames = @($cert.DnsNameList | ForEach-Object { $_.Unicode }) -join ', '
    Write-OK "Certificate found: Subject='$($cert.Subject)' SAN/DNS='$dnsNames' Thumbprint=$($cert.Thumbprint)"

    $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
    # The Hostname must be covered by the cert's CN or DNS SAN. If not, prefer a DNS name the cert carries.
    if ($dnsNames -and ($dnsNames -notmatch [regex]::Escape($fqdn))) {
        $first = @($cert.DnsNameList | ForEach-Object { $_.Unicode } | Where-Object { $_ })[0]
        if ($first) { Write-Warn "Cert does not list '$fqdn'; using cert DNS name '$first' as listener hostname instead."; $fqdn = $first }
    }

    if (-not (Set-WinRMHttpsListener -Thumbprint $cert.Thumbprint -Fqdn $fqdn -Port $Port)) {
        Write-Warn "Failed to create HTTPS listener -- skipping firewall step."
        return $null
    }
    Restart-Service -Name WinRM -Force
    Write-OK "HTTPS listener configured (Hostname=$fqdn)"

    # Local firewall (all profiles) -- takes effect immediately
    if (-not (Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $FwRuleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
        Write-OK "Local firewall rule created: $FwRuleName"
    } else {
        Set-NetFirewallRule -DisplayName $FwRuleName -Enabled True -ErrorAction SilentlyContinue
        Write-Skip "Local firewall rule already exists (ensured enabled)"
    }
    return $cert
}

# ============================================================================
# 1. AD CS role + Enterprise Root CA
# ============================================================================
Write-Step '1. AD CS role and Enterprise Root CA'

$RequiredFeatures = @('ADCS-Cert-Authority','ADCS-Web-Enrollment')
$Missing = @()
foreach ($f in $RequiredFeatures) {
    $w = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
    if ($w -and -not $w.Installed) { $Missing += $f }
}
if ($Missing.Count -gt 0) {
    Write-Info "Installing: $($Missing -join ', ')"
    Install-WindowsFeature -Name $Missing -IncludeManagementTools | Out-Null
    Write-OK 'Role services installed'
} else { Write-Skip 'Required AD CS role services already installed' }

# After Install-WindowsFeature the ADCSDeployment module is not auto-loaded into the
# current session (and may be absent / pending a reboot). Ensure it before using
# Install-AdcsCertificationAuthority.
Ensure-AdcsModule

$cfgName = Get-CertSvcConfigName
if (-not $cfgName) {
    Write-Info 'Configuring Enterprise Root CA...'
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
        -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' `
        -KeyLength 4096 -HashAlgorithmName SHA256 `
        -ValidityPeriod Years -ValidityPeriodUnits 10 `
        -CACommonName $CACommonName -Force | Out-Null
    $cfgName = Get-CertSvcConfigName
    Write-OK "Root CA configured: $cfgName"
} else { Write-Skip "CA already configured: $cfgName" }
Ensure-CertSvcRunning
Write-OK 'certsvc running confirmed'

# ============================================================================
# 2. Create certificate template + permissions + publish on CA
# ============================================================================
Write-Step '2. Create / publish certificate template'

$tmpl = New-WinRMTemplate -ConfigPath $ConfigPath -TemplateName $TemplateName -TemplateDisplayName $TemplateDisplayName
Grant-TemplateEnroll -TemplateDN $tmpl.DistinguishedName -GroupNames @('Domain Computers','Domain Controllers')

# Publish template on the CA (use template cn)
$caConfig = "$env:COMPUTERNAME\$cfgName"
$pub = certutil -config "$caConfig" -setcatemplates "+$TemplateName" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warn "certutil publish attempt 1 failed: $pub -- restarting certsvc and retrying"
    Restart-Service -Name certsvc -Force
    Start-Sleep 5
    $pub = certutil -config "$caConfig" -setcatemplates "+$TemplateName" 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Fail "Failed to publish template on CA: $pub" }
}
Restart-Service -Name certsvc -Force
Start-Sleep 3
Write-OK "Template published on CA: $TemplateName"

# ============================================================================
# 3. Create / link GPO
# ============================================================================
Write-Step '3. Create GPO and link to domain'

$Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $Gpo) {
    $Gpo = New-GPO -Name $GpoName
    Write-OK "GPO created: $GpoName"
} else { Write-Skip "GPO already exists: $GpoName" }

try {
    New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -Enforced Yes -ErrorAction Stop | Out-Null
    Write-OK 'Linked at domain root (Enforced)'
} catch {
    if ($_.Exception.Message -match 'already linked') { Write-Skip 'Already linked to the domain' }
    else { Write-Warn "Link warning: $($_.Exception.Message)" }
}

# ============================================================================
# 4. GPO policy: autoenrollment + firewall
# ============================================================================
Write-Step '4. GPO policy (autoenrollment / firewall)'

# 4-1) Certificate autoenrollment (AEPolicy=7: enable + renew + update). Registry CSE auto-registered / version bumped.
Set-GPRegistryValue -Name $GpoName `
    -Key 'HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment' `
    -ValueName 'AEPolicy' -Type DWord -Value 7 | Out-Null
Write-OK 'Certificate autoenrollment policy (AEPolicy=7) set'

# 4-2) Firewall 5986 inbound -- GPO PolicyStore method (works correctly). Firewall CSE auto-registered.
$store = "$DomainFQDN\$GpoName"
$exists = $false
try { if (Get-NetFirewallRule -PolicyStore $store -DisplayName $FwRuleName -ErrorAction SilentlyContinue) { $exists = $true } } catch {}
if (-not $exists) {
    New-NetFirewallRule -PolicyStore $store -DisplayName $FwRuleName -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort $WinRMHttpsPort -Profile Any | Out-Null
    Write-OK "GPO firewall rule created: $FwRuleName (TCP $WinRMHttpsPort, all profiles)"
} else {
    Write-Skip 'GPO firewall rule already exists'
}

# ============================================================================
# 5. Deploy GPO startup script (members configure their own HTTPS listener)
# ============================================================================
Write-Step '5. Deploy GPO startup script'

$PolicyPath = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\{$($Gpo.Id)}"
if (-not (Wait-ForPath -Path $PolicyPath -MaxSeconds 120)) { Write-Fail "SYSVOL path not ready: $PolicyPath" }

$StartupDir = Join-Path $PolicyPath 'Machine\Scripts\Startup'
if (-not (Test-Path $StartupDir)) { New-Item -ItemType Directory -Path $StartupDir -Force | Out-Null }

# --- Body of the member startup script (uses its own variables -> single-quoted here-string) ---
$StartupTemplate = @'
# Configure-WinRMHTTPS.ps1  (GPO Machine Startup Script)
$ErrorActionPreference = 'SilentlyContinue'
$TemplateName  = '{{TEMPLATE_NAME}}'
$CACommonName  = '{{CA_CN}}'
$Port          = {{PORT}}
$FwRuleName    = 'Ansible WinRM HTTPS (TCP {{PORT}})'
$ServerAuthOid = '1.3.6.1.5.5.7.3.1'

# Keep a local copy (startup script runs from SYSVOL; the retry task uses the local copy)
$workDir = Join-Path $env:ProgramData 'WinRMHTTPS'
if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }
$localSelf = Join-Path $workDir 'Configure-WinRMHTTPS.ps1'
try {
    if ($PSCommandPath -and ($PSCommandPath -ne $localSelf)) { Copy-Item -Path $PSCommandPath -Destination $localSelf -Force }
} catch {}

function Get-OurCert {
    Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
        ($_.Issuer -match [regex]::Escape($CACommonName)) -and
        (@($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }) -contains $ServerAuthOid)
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
}

Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

$cert = Get-OurCert
if (-not $cert) {
    certutil -pulse | Out-Null
    try { Get-Certificate -Template $TemplateName -CertStoreLocation Cert:\LocalMachine\My | Out-Null } catch {}
    for ($i=0; $i -lt 6; $i++) { Start-Sleep 10; $cert = Get-OurCert; if ($cert) { break } }
}

if ($cert) {
    $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
    $dns  = @($cert.DnsNameList | ForEach-Object { $_.Unicode } | Where-Object { $_ })
    if ($dns.Count -and ($dns -notcontains $fqdn)) { $fqdn = $dns[0] }

    # remove existing HTTPS listeners
    Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue |
        Where-Object { $_.Transport -eq 'HTTPS' } |
        ForEach-Object { Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address=$_.Address; Transport='HTTPS'} -ErrorAction SilentlyContinue } | Out-Null
    # clear ALL stale HTTP.sys SSL bindings on the port (any IP/hostname) -- cause of "internal error"
    $show = & netsh http show sslcert 2>$null
    foreach ($line in $show) {
        if ($line -match '^\s*IP:port\s*:\s*(\S+)' -and $matches[1] -match ":$Port`$") { & netsh http delete sslcert ipport=$($matches[1]) 2>&1 | Out-Null }
        elseif ($line -match '^\s*Hostname:port\s*:\s*(\S+)' -and $matches[1] -match ":$Port`$") { & netsh http delete sslcert hostnameport=$($matches[1]) 2>&1 | Out-Null }
    }
    & certutil -repairstore My $cert.Thumbprint 2>&1 | Out-Null
    Restart-Service -Name WinRM -Force -ErrorAction SilentlyContinue

    $ok = $false
    try {
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address='*'; Transport='HTTPS'} `
            -ValueSet @{Hostname=$fqdn; CertificateThumbprint=$cert.Thumbprint} -ErrorAction Stop | Out-Null
        $ok = $true
    } catch {
        # subject-less certs make WinRM's own bind fail with "internal error"; bind via netsh then
        # create the listener with an EMPTY thumbprint to share that binding.
        & netsh http delete sslcert ipport=0.0.0.0:$Port 2>&1 | Out-Null
        $b = & netsh http add sslcert ipport=0.0.0.0:$Port certhash=$($cert.Thumbprint) appid='{6FB5BB1B-0000-4F1A-9A0C-2E5D5F0E5A10}' certstorename=MY 2>&1
        if (($LASTEXITCODE -eq 0) -or (($b | Out-String) -match 'successfully')) {
            try {
                New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address='*'; Transport='HTTPS'} `
                    -ValueSet @{Hostname=$fqdn; CertificateThumbprint=''} -ErrorAction Stop | Out-Null
                $ok = $true
            } catch {
                try {
                    New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS -Hostname $fqdn -CertificateThumbPrint '' -Force -ErrorAction Stop | Out-Null
                    $ok = $true
                } catch {}
            }
        }
    }
    Restart-Service -Name WinRM -Force

    if (-not (Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $FwRuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
    }
    # Success -> remove the retry task
    if ($ok) { Unregister-ScheduledTask -TaskName 'Configure-WinRMHTTPS-Retry' -Confirm:$false -ErrorAction SilentlyContinue }
}
else {
    # Certificate not present yet (first-boot timing) -> register a 10-min retry task -> self-healing
    if (Test-Path $localSelf) {
        if (-not (Get-ScheduledTask -TaskName 'Configure-WinRMHTTPS-Retry' -ErrorAction SilentlyContinue)) {
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$localSelf`""
            $trg = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Hours 12)
            Register-ScheduledTask -TaskName 'Configure-WinRMHTTPS-Retry' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        }
    }
}
'@

$StartupScript = $StartupTemplate.
    Replace('{{TEMPLATE_NAME}}', $TemplateName).
    Replace('{{CA_CN}}',        $CACommonName).
    Replace('{{PORT}}',         "$WinRMHttpsPort")

Set-Content -Path (Join-Path $StartupDir 'Configure-WinRMHTTPS.ps1') -Value $StartupScript -Encoding UTF8

# psscripts.ini (PowerShell startup script definition) -- Unicode
$psIni = "[ScriptsConfig]`r`nStartExecutePSFirst=true`r`n[Startup]`r`n0CmdLine=Configure-WinRMHTTPS.ps1`r`n0Parameters="
Set-Content -Path (Join-Path $PolicyPath 'Machine\Scripts\psscripts.ini') -Value $psIni -Encoding Unicode
Write-OK 'SYSVOL startup script + psscripts.ini deployed'

# Register the Scripts CSE + sync version (without this the startup script NEVER runs!)
# CSE GUID {42B5FAAE-...} , Tool ext GUID {40B6664F-...}
Add-GpoMachineCSE -GpoId $Gpo.Id -DomainDN $DomainDN -CseAndTools @(
    '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}',
    '{40B6664F-4972-11D1-A7CA-0000F87571E3}'
)
Update-GpoComputerVersion -GpoId $Gpo.Id -DomainDN $DomainDN `
    -GptIniPath (Join-Path $PolicyPath 'GPT.INI') -DisplayName $GpoName

# ============================================================================
# 6. Configure the DC itself (immediate) -- certificate + HTTPS listener + local firewall
# ============================================================================
Write-Step '6. Configure DC WinRM HTTPS'

# Ensure root CA trust
$root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match [regex]::Escape($CACommonName) } | Select-Object -First 1
if (-not $root) {
    $tmpCer = Join-Path $LogDir 'rootca.cer'
    certutil -ca.cert $tmpCer 2>&1 | Out-Null
    if (Test-Path $tmpCer) { Import-Certificate -FilePath $tmpCer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null }
    $root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match [regex]::Escape($CACommonName) } | Select-Object -First 1
}
if ($root) { Write-OK "Root CA trust confirmed: $($root.Thumbprint)" } else { Write-Warn 'Could not confirm root CA in trust store' }

# Export the Root CA certificate to the Administrator Desktop so the Ansible control
# node (WSL) can copy it (\\wsl: or /mnt/c) and trust psrp/HTTPS communication.
if ($root) {
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path $desktop)) { $desktop = Join-Path $env:USERPROFILE 'Desktop' }
    if (-not (Test-Path $desktop)) { $desktop = Join-Path $env:SystemDrive 'Users\Administrator\Desktop' }
    if (-not (Test-Path $desktop)) { New-Item -ItemType Directory -Path $desktop -Force | Out-Null }
    try {
        $rootCerPath = Join-Path $desktop 'rootca.cer'   # DER (.cer) - the WSL script auto-converts to PEM
        Export-Certificate -Cert $root -FilePath $rootCerPath -Type CERT -Force | Out-Null
        # Also save a PEM (Base64) copy for convenience
        $rootPemPath = Join-Path $desktop 'rootca.pem'
        $b64 = [Convert]::ToBase64String($root.RawData, 'InsertLineBreaks')
        Set-Content -Path $rootPemPath -Value ("-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----") -Encoding Ascii
        Write-OK "Root CA exported for Ansible -> $rootCerPath (+ rootca.pem)"
        Write-Info "On WSL:  cp /mnt/c/Users/Administrator/Desktop/rootca.cer ~/automation/certs/rootca.cer"
    } catch { Write-Warn "Root CA export failed: $($_.Exception.Message)" }
}

$DcCert = Ensure-LocalWinRMHttps -CaCn $CACommonName -Port $WinRMHttpsPort -FwRuleName $FwRuleName

# ============================================================================
# 7. Validation
# ============================================================================
Write-Step '7. Final validation'
$pass = $true

if ((certutil -ping 2>&1) -match 'interface is alive') { Write-OK '[V1] CA service responding' } else { Write-Warn '[V1] No CA response'; $pass=$false }

if ((certutil -catemplates 2>&1) | Select-String -SimpleMatch $TemplateName -Quiet) { Write-OK "[V2] Template published on CA: $TemplateName" } else { Write-Warn "[V2] Template not published"; $pass=$false }

$v3cert = if ($DcCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { $DcCert } else { Get-ServerAuthCert -CaCn $CACommonName }
if ($v3cert -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { Write-OK "[V3] DC certificate valid ($([Math]::Round(($v3cert.NotAfter-(Get-Date)).TotalDays)) days to expiry)" } else { Write-Warn '[V3] No usable DC certificate'; $pass=$false }

$listener = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue | Where-Object { $_.Transport -eq 'HTTPS' }
if ($listener) {
    $effTp = $listener.CertificateThumbprint
    if (-not $effTp) {
        # Shared binding: the cert is bound at the HTTP.sys layer -> read its hash from netsh
        $show = & netsh http show sslcert 2>$null
        $cur = $null
        foreach ($line in $show) {
            if     ($line -match '^\s*IP:port\s*:\s*(\S+)')       { $cur = $matches[1] }
            elseif ($line -match '^\s*Hostname:port\s*:\s*(\S+)') { $cur = $matches[1] }
            elseif ($cur -and ($cur -match ":$WinRMHttpsPort$") -and ($line -match '^\s*Certificate Hash\s*:\s*([0-9A-Fa-f]+)')) { $effTp = $matches[1]; break }
        }
        if ((-not $effTp) -and ($DcCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2])) { $effTp = $DcCert.Thumbprint }
    }
    Write-OK "[V4] HTTPS listener active (Thumbprint: $effTp)"
} else { Write-Warn '[V4] No HTTPS listener'; $pass=$false }

if (Test-NetConnection -ComputerName localhost -Port $WinRMHttpsPort -InformationLevel Quiet) { Write-OK "[V5] TCP $WinRMHttpsPort listening" } else { Write-Warn "[V5] TCP $WinRMHttpsPort not listening"; $pass=$false }

$fw = Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
if ($fw -and $fw.Enabled -eq 'True') { Write-OK '[V6] Local firewall rule active' } else { Write-Warn '[V6] Local firewall rule disabled/missing'; $pass=$false }

if (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue) { Write-OK "[V7] GPO exists: $GpoName" } else { Write-Warn "[V7] GPO missing"; $pass=$false }

$cseChk = (Get-ADObject -Identity "CN={$($Gpo.Id)},CN=Policies,CN=System,$DomainDN" -Properties gPCMachineExtensionNames).gPCMachineExtensionNames
if ($cseChk -match '42B5FAAE') { Write-OK '[V8] Startup script CSE registered (clients will process the script)' } else { Write-Warn '[V8] Scripts CSE not registered'; $pass=$false }

# ============================================================================
# 8. Ansible connection guidance
# ============================================================================
Write-Step '8. Ansible (psrp) connection guidance'
$dcFqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
Write-Host @"

  -- On the control node (Linux) -------------------------------------
  # 1) Dependencies
  pip install pypsrp

  # 2) Root CA cert was auto-exported to the Administrator Desktop by this script:
  #       C:\Users\Administrator\Desktop\rootca.cer  (and rootca.pem)
  #    Copy it to the control node (WSL example):
  #       cp /mnt/c/Users/Administrator/Desktop/rootca.cer ~/automation/certs/rootca.cer
  #    (if needed)  openssl x509 -inform DER -in rootca.cer -out vclass-root-ca.pem

  # inventory.ini
  [windows]
  $dcFqdn

  [windows:vars]
  ansible_connection=psrp
  ansible_port=$WinRMHttpsPort
  ansible_user=Administrator
  ansible_password=<password>
  ansible_psrp_protocol=https
  ansible_psrp_auth=ntlm                       # or kerberos / negotiate
  ansible_psrp_cert_validation=validate
  ansible_psrp_ca_trust_path=/etc/ansible/certs/vclass-root-ca.pem

  # Connectivity test
  ansible windows -m ansible.windows.win_ping
  --------------------------------------------------------------------
  NOTE: psrp 'certificate' auth needs an extra client-certificate-to-account
        mapping in AD. With only a server certificate configured (this setup),
        ntlm/kerberos auth is recommended.
"@ -ForegroundColor DarkGray

Write-Host "`n======================================" -ForegroundColor Cyan
if ($pass) {
    Write-Host "  [PASS] All checks passed -- DC configuration complete" -ForegroundColor Green
    Write-Host "  Member computers: applied automatically on 'gpupdate /force' or reboot after domain join" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Some checks reported WARN -- review the messages above" -ForegroundColor Yellow
}
Write-Host "======================================`n" -ForegroundColor Cyan

try { Stop-Transcript | Out-Null } catch {}
