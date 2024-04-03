$ErrorActionPreference = "Stop"
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath =  ($mountPath.Replace('\', '/')).TrimEnd('/')
$env:PATH = $env:PATH + ";$mountPath/Windows/System32;$mountPath/k/antrea/bin;$mountPath/openvswitch/usr/bin;$mountPath/openvswitch/usr/sbin"

function ParseKubeAPIServer {
    param (
        [string] $kubeProxyConfigFile
    )
    if (Test-Path -Path $kubeProxyConfigFile) {
        $content = Get-Content -Path $kubeProxyConfigFile -Raw
        $lines = $content -split '\r?\n'
        foreach ($line in $lines) {
            if ($line -match '^\s*server:\s*(?:https?://)?(\S+)') {
                return $matches[1]
            }
        }
    }
    return ""
}

function RewriteAntreaAgentConfig {
    param (
        [string] $kubeProxyConfigFile,
        [string] $antreaConfigFile
    )
    $antreaConfigContent = Get-Content -Path $antreaConfigFile -Raw
    $lines = $content -split '\r?\n'
    $proxyAllEnabled = $False
    $needOverride = $False
    $leadingWhitespace = ""
    $lineNo = 0
    for ($i = 0; $i -lt $content.Count; $i++) {
        $line = $content[$i]
        if ($line -match '^\s*proxyAll:\s+true$') {
            $proxyAllEnabled = $True
        }
        if ($line -match '^(\s*)(?:#)?kubeAPIServerOverride:\s*""$') {
            $lineNo = $i
            $leadingWhitespace = $matches[1]
            $needOverride = $True
        }
    }
    if ($proxyAllEnabled -and $needOverride) {
        $serverURL = ParseKubeAPIServer -kubeProxyConfigFile $kubeProxyConfigFile
        if ($serverURL) {
            $content[$lineNo] = "${leadingWhitespace}kubeAPIServerOverride: `"$serverURL`""
            $content | Set-Content -Path $antreaConfigFile
        }
    }
}

RewriteAntreaAgentConfig -kubeProxyConfigFile ${mountPath}/etc/kube-proxy/kubeconfig.conf -antreaConfigFile ${mountPath}/etc/antrea/antrea-agent.conf

& antrea-agent --config=$mountPath/etc/antrea/antrea-agent.conf --logtostderr=false --log_dir=c:/var/log/antrea --alsologtostderr --log_file_max_size=100 --log_file_max_num=4 --v=0
