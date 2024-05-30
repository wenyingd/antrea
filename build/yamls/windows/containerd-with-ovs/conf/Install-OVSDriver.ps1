$ErrorActionPreference = "Stop"
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath = ($mountPath.Replace('\', '/')).TrimEnd('/')
$OVSInstallScript = "$mountPath\k\antrea\Install-OVS.ps1"
if (-not (Test-Path $OVSInstallScript)) {
  Write-Host "Installation script not found: $OVSInstallScript, you may be using an invalid antrea-windows container image"
  exit 1
}
$installOVSJob = Start-Job -ScriptBlock {& $OVSInstallScript -InstallUserspace $false -LocalFile $mountPath\openvswitch}
$installOVSJob | Receive-Job -Wait
Remove-Job -Id $installOVSJob.Id
$state = $installOVSJob.State
if ($state -ne "Completed") {
  Write-Host "Failed to install OVS with state: $state"
  exit 1
}
Write-Host "Completed to install OVS"
