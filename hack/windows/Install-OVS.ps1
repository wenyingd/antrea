<#
  .SYNOPSIS
  Installs Windows OpenvSwitch from a web location or local file.

  .PARAMETER DownloadURL
  The URL of the OpenvSwitch package to be downloaded.

  .PARAMETER OVSInstallDir
  The target installation directory. The default path is "C:\openvswitch".

  .PARAMETER LocalFile
  Specifies the path of a local OpenvSwitch package to be used for installation.
  When the param is used, "DownloadURL" is ignored.

  .PARAMETER InstallUserspace
  Specifies whether OVS userspace processes are included in the installation. If false, these processes will not 
  be installed as a Windows service on the host.

  .PARAMETER LocalSSLFile
  Specifies the path of a local SSL package to be used for installation.
#>
Param(
    [parameter(Mandatory = $false)] [string] $DownloadURL,
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch",
    [parameter(Mandatory = $false)] [string] $LocalFile,
    [parameter(Mandatory = $false)] [bool] $InstallUserspace = $true,
    [parameter(Mandatory = $false)] [string] $LocalSSLFile
)

$ErrorActionPreference = "Stop"
$DefaultOVSDownloadURL = "https://downloads.antrea.io/ovs/ovs-3.0.5-antrea.1-win64.zip"
# Use a SHA256 hash to ensure that the downloaded archive is correct.
$DefaultOVSPublishedHash = '813a0c32067f40ce4aca9ceb7cd745a120e26906e9266d13cc8bf75b147bb6a5'
# $MininalVCRedistVersion is the minimal version required by the provided Windows OVS binary. If a higher
# version of VC redistributable file exists on the Windows host, we can skip the installation.
$MininalVCRedistVersion="14.12.25810"

$WorkDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$InstallLog = "$WorkDir\install_ovs.log"
$PowerShellModuleBase = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
$OVSZip=""

function PrepareOVSLocalFiles() {
    $OVSDownloadURL = $DefaultOVSDownloadURL
    $desiredOVSPublishedHash = $DefaultOVSPublishedHash
    if ($LocalFile -ne "") {
        if (-not (Test-Path $LocalFile)){
            Log "Path $LocalFile doesn't exist, exit"
            exit 1
        }

        $ovsFile = Get-Item $LocalFile
        if ($ovsFile -is [System.IO.DirectoryInfo])  {
            return $ovsFile.FullName
        }

        # $ovsFile as a zip file is supported
        $attributes = $ovsFile.Attributes
        if (("$attributes" -eq "Archive") -and ($ovsFile.Extension -eq ".zip" ) ) {
            $OVSZip = $LocalFile
            $OVSDownloadURL = ""
            $OVSPublishedHash = ""
        } else {
            Log "Unsupported local file $LocalFile with attributes '$attributes'"
            exit 1
        }
    } else {
        $OVSZip = "$WorkDir\ovs-win64.zip"
        if ($DownloadURL -ne "" -and $DownloadURL -ne "$OVSDownloadURL") {
            $OVSDownloadURL = $DownloadURL
            $desiredOVSPublishedHash = ""
        }
    }

    # Extract zip file to $OVSInstallDir
    if (Test-Path -Path $OVSInstallDir) {
        Log "$OVSInstallDir already exists, exit OVS installation."
        exit 1
    }
    $removeZipFile = $false
    if ($OVSDownloadURL -ne "") {
        DownloadOVS -localZipFile $OVSZip -downloadURL $OVSDownloadURL -desiredHash $desiredOVSPublishedHash
        $removeZipFile = $true
    }
    $ovsInstallParentPath = Split-Path -Path $OVSInstallDir -Parent
    Expand-Archive -Path $OVSZip -DestinationPath $ovsInstallParentPath | Out-Null
    if ($removeZipFile) {
        rm $OVSZip
    }
    return $OVSInstallDir
}

function Log($Info) {
    $time = $(get-date -Format g)
    "$time $Info `n`r" | Tee-Object $InstallLog -Append | Write-Host
}

function ServiceExists($ServiceName) {
    If (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        return $true
    }
    return $false
}

function CheckIfOVSInstalled() {
    if (Test-Path -Path $OVSInstallDir) {
        Log "$OVSInstallDir already exists, exit OVS installation."
        exit 1
    }
    If (ServiceExists("ovs-vswitchd")) {
        Log "Found existing OVS service, exit OVS installation."
        exit 0
    }
}

function DownloadOVS() {
    param (
        [parameter(Mandatory = $true)] [string] $localZipFile,
        [parameter(Mandatory = $true)] [string] $downloadURL,
        [parameter(Mandatory = $true)] [string] $desiredHash
    )
    Log "Downloading OVS package from $downloadURL to $localZipFile"
    curl.exe -sLo $localZipFile $downloadURL
    If (!$?) {
        Log "Download OVS failed, URL: $downloadURL"
        exit 1
    }

    if ($desiredHash-ne "") {
        $fileHash = Get-FileHash $localZipFile
        If ($fileHash.Hash -ne $desiredHash) {
            Log "SHA256 mismatch for OVS download"
            exit 1
        }
    }

    Log "Download OVS package success."
}

function InstallOVS() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSInstallDir
    )
    # Install powershell modules
    $OVSScriptsPath = "${OVSInstallDir}\scripts"
    CheckAndInstallScripts -OVSScriptsPath $OVSScriptsPath

    # Install VC redistributables.
    $OVSRedistDir="${OVSInstallDir}\redist"
    # Check if the VC redistributable is already installed. If not installed, or the installed version
    # is lower than $MininalVCRedistVersion, install VC redistributable files provided in the container.
    CheckAndInstallVCRedists -VCRedistPath $OVSRedistDir -VCRedistsVersion $MininalVCRedistVersion

    # Install OVS driver.
    $OVSDriverDir = "${OVSInstallDir}\driver"
    Log "Installing OVS kernel driver"
    CheckAndInstallOVSDriver -OVSDriverPath $OVSDriverDir

    if ($InstallUserspace -eq $true) {
        InstallOVSServices -OVSInstallPath $OVSInstallDir
    }
}

function InstallOVSServices() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSInstallPath
    )

    # Remove the existing OVS Services to avoid issues.
    If (ServiceExists("ovs-vswitchd")) {
        stop-service ovs-vswitchd
        sc.exe delete ovs-vswitchd
    }
    if (ServiceExists("ovsdb-server")) {
        stop-service ovsdb-server
        sc.exe delete ovsdb-server
    }

    $usrBinPath="${OVSInstallPath}\usr\bin"
    $usrSbinPath="${OVSInstallPath}\usr\sbin"
    $OVSBinPaths="${usrBinPath};${usrSbinPath}"
    InstallOpenSSLFiles "$OVSBinPaths"

    # Create log and run dir.
    $OVSLogDir = "${OVSInstallPath}\var\log\openvswitch"
    if (-not (Test-Path $OVSLogDir)) {
        mkdir -p $OVSLogDir | Out-Null
    }
    $OVSRunDir = "${OVSInstallPath}\var\run\openvswitch"
    if (-not (Test-Path $OVSRunDir)) {
        mkdir -p $OVSRunDir | Out-Null
    }

    # Install OVS Services and configure OVSDB.
    ConfigOVS -OVSInstallPath $OVSInstallPath

    # Add OVS usr/bin and usr/sbin to System path.
    $envPaths = $env:Path -split ";" | Select-Object -Unique
    if (-not $envPaths.Contains($usrBinPath)) {
        $envPaths += $usrBinPath
    }
    if (-not $envPaths.Contains($usrSbinPath)) {
        $envPaths += $usrSbinPath
    }
    $env:Path = [system.String]::Join(";", $envPaths)
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
}

function CheckAndInstallScripts {
    param (
        [Parameter(Mandatory = $true)] [String]$OVSScriptsPath
    )
    if (Test-Path $OVSScriptsPath) {
        Log "Installing powershell modules."
        $PSModuleFiles = Get-ChildItem "$OVSScriptsPath" -Filter *.psm1
        $PSModuleFiles | ForEach-Object {
            $PSModulePath = Join-Path -Path $PowerShellModuleBase -ChildPath $_.BaseName
            if (!(Test-Path $PSModulePath)) {
                Log "Installing $_"
                mkdir -p $PSModulePath
                Copy-Item $_.FullName $PSModulePath
            }
        }
    }
}

function CheckAndInstallVCRedists {
    param (
        [Parameter(Mandatory = $true)] [String]$VCRedistPath,
        [Parameter(Mandatory = $true)] [String]$VCRedistsVersion
    )
    $mininalVersion = [version]$VCRedistsVersion
    $existingVCRedists = getInstalledVcRedists
    foreach ($redist in $existingVCRedists) {
        $installedVersion = [version]$redist.Version
        # VC redists files with a higher version are installed, return.
        if ($installedVersion -ge $mininalVersion) {
            return
        }
    }
    # Install the provided VC redistributable files.
    Get-ChildItem $VCRedistPath -Filter *.exe | ForEach-Object {
        Start-Process -FilePath $_.FullName -Args '/install /passive /norestart' -Verb RunAs -Wait
    }
}

function CheckAndInstallOVSDriver {
    param (
        [Parameter(Mandatory = $true)]
        [String]$OVSDriverPath
    )

    $expVersion = [version]$(Get-Item $OVSDriverPath\ovsext.sys).VersionInfo.ProductVersion
    $ovsInstalled = $(netcfg -q ovsext) -like "*is installed*"
    $installedDrivers = getInstalledOVSDrivers

    # OVSext driver with the desired version is already installed, return
    if ($ovsInstalled -and ($installedDrivers.Length -eq 1) -and ($installedDrivers[0].DriverVersion -eq $expVersion)){
        return
    }

    # Uninstall the existing driver which is with a different version.
    if ($ovsInstalled) {
        netcfg -u ovsext
    }

    # Clean up the installed ovsext drivers packages.
    foreach ($driver in $installedDrivers) {
        $publishdName = $driver.PublishedName
        pnputil.exe -d $publishdName
    }

    # Import OVSext driver certificate to TrustedPublisher and Root.
    $DriverFile="$OVSDriverPath\ovsext.sys"
    $CertificateFile = "$OVSDriverPath\package.cer"
    $ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
    $Cert = (Get-AuthenticodeSignature $DriverFile).SignerCertificate
    [System.IO.File]::WriteAllBytes($CertificateFile, $Cert.Export($ExportType))
    Import-Certificate -FilePath "$CertificateFile" -CertStoreLocation cert:\LocalMachine\TrustedPublisher
    Import-Certificate -FilePath "$CertificateFile" -CertStoreLocation cert:\LocalMachine\Root

    # Install the OVSext driver with the desired version
    $result = netcfg -l $OVSDriverPath/ovsext.inf -c s -i OVSExt
    if ($result -like '*failed*') {
        Write-Host "Failed to install OVSExt driver: $result"
        exit 1
    }
    Log "OVSExt driver has been installed"
}

function getInstalledVcRedists {
    # Get all installed Visual C++ Redistributables installed components
    $VcRedists = listInstalledSoftware -SoftwareLike 'Microsoft Visual C++'

    # Add Architecture property to each entry
    $VcRedists | ForEach-Object { If ( $_.Name.ToLower().Contains("x64") ) `
        { $_ | Add-Member -NotePropertyName "Architecture" -NotePropertyValue "x64" } }

    return $vcRedists
}

function listInstalledSoftware {
    param (
        [parameter(Mandatory = $false)] [string] $SoftwareLike
    )
    Begin {
        $SoftwareOutput = @()
        $InstalledSoftware = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*)
    }
    Process {
        Try
        {
            if ($SoftwareLike -ne "") {
                $nameFilter = "${SoftwareLike}*"
                $InstalledSoftware = $InstalledSoftware |
                        Where-Object {$_.DisplayName -like "$nameFilter"}
            }

            $SoftwareOutput = $InstalledSoftware |
                    Select-Object -Property @{
                        Name = 'Date Installed'
                        Exp  = {
                            $_.Installdate
                        }
                    }, @{
                        Name = 'Version'
                        Exp  = {
                            $_.DisplayVersion
                        }
                    }, @{
                        Name = 'Name'
                        Exp = {
                            $_.DisplayName
                        }
                    }, UninstallString
        }
        Catch
        {
            # get error record
            [Management.Automation.ErrorRecord]$e = $_

            # retrieve information about runtime error
            $info = New-Object -TypeName PSObject -Property @{
                Exception = $e.Exception.Message
                Reason    = $e.CategoryInfo.Reason
                Target    = $e.CategoryInfo.TargetName
                Script    = $e.InvocationInfo.ScriptName
                Line      = $e.InvocationInfo.ScriptLineNumber
                Column    = $e.InvocationInfo.OffsetInLine
            }

            # output information. Post-process collected info, and log info (optional)
            $info
        }
    }

    End{
        $SoftwareOutput | Sort-Object -Property Name
    }
}

# getInstalledOVSDrivers lists the existing drivers on Windows host, and uses "ovsext" as a filter
# on the "OriginalName" field of the drivers. As the output of "pnputil.exe" is not structured, the
# function translates to structured objects first, and then apply the filter.
#
# A sample of the command output is like this,
#
# $ pnputil.exe /enum-drivers
# Microsoft PnP Utility
#
# Published Name:     oem3.inf
# Original Name:      efifw.inf
# Provider Name:      VMware, Inc.
# Class Name:         Firmware
# Class GUID:         {f2e7dd72-6468-4e36-b6f1-6488f42c1b52}
# Driver Version:     04/24/2017 1.0.0.0
# Signer Name:        Microsoft Windows Hardware Compatibility Publisher
#
# Published Name:     oem5.inf
# Original Name:      pvscsi.inf
# Provider Name:      VMware, Inc.
# Class Name:         Storage controllers
# Class GUID:         {4d36e97b-e325-11ce-bfc1-08002be10318}
# Driver Version:     04/06/2018 1.3.10.0
# Signer Name:        Microsoft Windows Hardware Compatibility Publishe
#
# Published Name:     oem9.inf
# Original Name:      vmci.inf
# Provider Name:      VMware, Inc.
# Class Name:         System devices
# Class GUID:         {4d36e97d-e325-11ce-bfc1-08002be10318}
# Driver Version:     07/11/2019 9.8.16.0
# Signer Name:        Microsoft Windows Hardware Compatibility Publisher
#
function getInstalledOVSDrivers {
    $pnputilOutput = pnputil.exe /enum-drivers
    $drivers = @()
    $lines = $pnputilOutput -split "`r`n"
    $driverlines = @()
    foreach ($line in $lines) {
        # Ignore the title line "Microsoft PnP Utility" from the output.
        if ($line -like "*Microsoft PnP Utility*") {
            continue
        }
        if ($line.Trim() -eq "") {
            if ($driverlines.Count -gt 0) {
                $driver = $(parseDriver $driverlines)
                $drivers += $driver
                $driverlines = @()
            }
            continue
        }
        $driverlines += $line
    }
    if ($driverlines.Count -gt 0) {
        $driver = parseDriver $driverlines
        $drivers += $driver
    }
    $drivers = $drivers | Where-Object { $_.OriginalName -like "ovsext*"}
    return $drivers
}

function parseDriver {
    param (
        [String[]]$driverlines
    )
    $driver = [PSCustomObject]@{
        PublishedName = $null
        ProviderName = $null
        ClassName = $null
        DriverVersion = $null
        InstalledDate = $null
        SignerName = $null
        ClassGUID = $null
        OriginalName = $null
    }
    $driverlines | ForEach-Object {
        if ($_ -match "Published Name\s*:\s*(.+)") {
            $driver.PublishedName = $matches[1].Trim()
        }
        elseif ($_ -match "Provider Name\s*:\s*(.+)") {
            $driver.ProviderName = $matches[1].Trim()
        }
        elseif ($_ -match "Class Name\s*:\s*(.+)") {
            $driver.ClassName = $matches[1].Trim()
        }
        elseif ($_ -match "Driver Version\s*:\s*(.+)") {
            $dateAndVersion = $matches[1].Trim() -split " "
            $driver.DriverVersion = [version]$dateAndVersion[1]
            $driver.InstalledDate = $dateAndVersion[0]
        }
        elseif ($_ -match "Signer Name\s*:\s*(.+)") {
            $driver.SignerName = $matches[1].Trim()
        }
        elseif ($_ -match "Class GUID\s*:\s*(.+)") {
            $driver.ClassGUID = $matches[1].Trim()
        }
        elseif ($_ -match "Original Name\s*:\s*(.+)") {
            $driver.OriginalName = $matches[1].Trim()
        }
    }
    return $driver
}

function InstallOpenSSLFiles {
    param (
        [parameter(Mandatory = $true)] [string] $destinationPaths
    )

    # Check if SSL library has been installed
    $paths = $destinationPaths.Split(";")
    foreach($path in $paths) {
        if ((Test-Path "$path/ssleay32.dll" -PathType Leaf) -and (Test-Path "$path/libeay32.dll" -PathType Leaf)) {
            Log "Found existing SSL library."
            return
        }
    }
    if ($LocalSSLFile) {
        if ($LocalSSLFile -like "*.zip") {
            Log "Install local SSL library."
            Expand-Archive $LocalSSLFile -DestinationPath openssl
        } else {
            Log "The local SSL package must be in ZIP format, exit"
            exit 1
        }
    } else {
        $SSLZip = "openssl-1.0.2u-x64_86-win64.zip"
        $SSLMD5 = "E723E1C479983F35A0901243881FA046"
        $SSLDownloadURL = "https://github.com/IndySockets/OpenSSL-Binaries/raw/21d81384bfe589273e6b2ac1389c40e8f0ca610d/$SSLZip"
        curl.exe -LO $SSLDownloadURL
        If (!$?) {
            Log "Download SSL files failed, URL: $SSLDownloadURL"
            Log "Please install ssleay32.dll and libeay32.dll to $OVSInstallDir\usr\sbin\ manually"
            exit 1
        }
        $MD5Result = Get-FileHash $SSLZip -Algorithm MD5 | Select -ExpandProperty "Hash"
        If ($MD5Result -ne $SSLMD5){
            Log "Wrong md5sum, Please check the file integrity"
            exit 1
        }
        Expand-Archive $SSLZip -DestinationPath openssl
        rm $SSLZip
    }
    $destinationPaths -Split ";" | Foreach-Object {
        cp -Force openssl/*.dll $_\
    }
    rm -Recurse -Force openssl
}

function ConfigOVS() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSInstallPath
    )
    # Antrea Pod runs as NT AUTHORITY\SYSTEM user on Windows, antrea-ovs container writes
    # PID and conf.db files to $OVSInstallDir on Windows Node when it is running.
    icacls $OVSInstallPath /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T

    # Create ovsdb config file
    $OVS_DB_SCHEMA_PATH = "$OVSInstallPath\usr\share\openvswitch\vswitch.ovsschema"
    $OVS_DB_PATH = "$OVSInstallPath\etc\openvswitch\conf.db"
    if ($(Test-Path $OVS_DB_SCHEMA_PATH) -and !$(Test-Path $OVS_DB_PATH)) {
        Log "Creating ovsdb file"
        & $OVSInstallPath\usr\bin\ovsdb-tool.exe create "$OVS_DB_PATH" "$OVS_DB_SCHEMA_PATH"
    }
    # Create and start ovsdb-server service.
    Log "Create and start ovsdb-server service"
    sc.exe create ovsdb-server binPath= "$OVSInstallPath\usr\sbin\ovsdb-server.exe $OVSInstallPath\etc\openvswitch\conf.db  -vfile:info --remote=punix:db.sock  --remote=ptcp:6640  --log-file  --pidfile --service" start= auto
    sc.exe failure ovsdb-server reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovsdb-server
    # Create and start ovs-vswitchd service.
    Log "Create and start ovs-vswitchd service."
    sc.exe create ovs-vswitchd binpath="$OVSInstallPath\usr\sbin\ovs-vswitchd.exe  --pidfile -vfile:info --log-file  --service" start= auto depend= "ovsdb-server"
    sc.exe failure ovs-vswitchd reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovs-vswitchd
    # Set OVS version.
    $OVS_VERSION=$(Get-Item $OVSInstallPath\driver\OVSExt.sys).VersionInfo.ProductVersion
    Log "Set OVS version to: $OVS_VERSION"
    & $OVSInstallPath\usr\bin\ovs-vsctl.exe --no-wait set Open_vSwitch . ovs_version=$OVS_VERSION
}

if (($LocalFile -ne "") -and ($DownloadURL -ne "")) {
    Log "LocalFile and DownloadURL are mutually exclusive, exit"
    exit 1
}
Log "Installation log location: $InstallLog"

$OVSPath = PrepareOVSLocalFiles
InstallOVS -OVSInstallDir $OVSPath

Log "OVS Installation Complete!"
