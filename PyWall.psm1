Set-StrictMode -Version Latest

function Invoke-PyWallApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Token,
        [string]$BaseUrl = 'http://127.0.0.1:8765',
        [ValidateSet('GET','POST')][string]$Method = 'GET',
        [Parameter(Mandatory=$true)][string]$Path,
        [object]$Body
    )
    if ($Token.Length -lt 16) { throw 'PyWall API token must be at least 16 characters.' }
    $headers = @{ Authorization = "Bearer $Token"; Accept = 'application/json' }
    $params = @{ Uri = ($BaseUrl.TrimEnd('/') + $Path); Method = $Method; Headers = $headers; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 8 -Compress)
        $params.ContentType = 'application/json'
    }
    Invoke-RestMethod @params
}

function Get-PyWallStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Token, [string]$BaseUrl = 'http://127.0.0.1:8765')
    (Invoke-PyWallApi -Token $Token -BaseUrl $BaseUrl -Path '/v1/status').status
}

function Block-PyWallIP {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Token, [Parameter(Mandatory=$true)][string]$IP, [ValidateSet('Inbound','Outbound')][string]$Direction = 'Outbound', [string]$BaseUrl = 'http://127.0.0.1:8765')
    Invoke-PyWallApi -Token $Token -BaseUrl $BaseUrl -Method POST -Path '/v1/firewall/block-ip' -Body @{ ip = $IP; direction = $Direction }
}

function Allow-PyWallPort {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Token, [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$Port, [ValidateSet('TCP','UDP','Any')][string]$Protocol = 'TCP', [ValidateSet('Inbound','Outbound')][string]$Direction = 'Outbound', [string]$BaseUrl = 'http://127.0.0.1:8765')
    Invoke-PyWallApi -Token $Token -BaseUrl $BaseUrl -Method POST -Path '/v1/firewall/allow-port' -Body @{ port = $Port; protocol = $Protocol; direction = $Direction }
}

function Get-PyWallFleet {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Token, [string]$BaseUrl = 'http://127.0.0.1:8765')
    (Invoke-PyWallApi -Token $Token -BaseUrl $BaseUrl -Path '/v1/fleet').fleet
}

function Update-PyWallFleet {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Token, [string]$BaseUrl = 'http://127.0.0.1:8765')
    (Invoke-PyWallApi -Token $Token -BaseUrl $BaseUrl -Method POST -Path '/v1/fleet/refresh').fleet
}

function Export-PyWallConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Token, [Parameter(Mandatory=$true)][securestring]$Passphrase, [Parameter(Mandatory=$true)][string]$Path, [string]$BaseUrl = 'http://127.0.0.1:8765')
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr); $response = Invoke-PyWallApi -Token $Token -BaseUrl $BaseUrl -Method POST -Path '/v1/config/export' -Body @{ passphrase = $plain } }
    finally { if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
    if (-not $response.ok) { throw $(if ($response.error) { $response.error } else { 'PyWall config export failed.' }) }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllBytes($fullPath, [Convert]::FromBase64String($response.payload))
    $fullPath
}

Export-ModuleMember -Function Invoke-PyWallApi, Get-PyWallStatus, Block-PyWallIP, Allow-PyWallPort, Get-PyWallFleet, Update-PyWallFleet, Export-PyWallConfig
