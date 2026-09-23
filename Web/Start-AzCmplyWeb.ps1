#Requires -Version 7.2
<#
    .SYNOPSIS
    Serves the AzCmply web page on this computer, for use with your own app registration.
    .DESCRIPTION
    A minimal static web server for the site folder (http://localhost:<Port>/). Register http://localhost:<Port>/ as a
    single-page application redirect URI on your app registration (New-AzCmplyAppRegistration.ps1 does that), open the
    page and sign in. The server only serves files; everything else happens in the browser.
    .PARAMETER Port
    Port to listen on. Default 8400.
    .PARAMETER NoBrowser
    Does not open the page in the default browser.
    .EXAMPLE
    .\Start-AzCmplyWeb.ps1
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.lieben.nu
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [ValidateRange(1024, 65535)][int]$Port = 8400,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot 'site')).Path
$types = @{
    '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.mjs' = 'text/javascript; charset=utf-8'
    '.css' = 'text/css; charset=utf-8'; '.json' = 'application/json; charset=utf-8'; '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.ico' = 'image/x-icon'
}
$prefix = "http://localhost:$Port/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "AzCmply is served at $prefix (Ctrl+C stops the server)."
Write-Host "Redirect URI to register on your app registration, as a single-page application: $prefix"
if (-not $NoBrowser) { Start-Process $prefix }
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $response = $context.Response
        try {
            $relative = [uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))
            if (-not $relative -or $relative.EndsWith('/')) { $relative += 'index.html' }
            $path = [System.IO.Path]::GetFullPath((Join-Path $root $relative))
            $response.Headers['X-Content-Type-Options'] = 'nosniff'
            $response.Headers['Referrer-Policy'] = 'no-referrer'
            $response.Headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
            $response.Headers['Content-Security-Policy'] = "frame-ancestors 'self'"
            $response.Headers['Cache-Control'] = 'no-cache'
            if (-not $path.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar) -or -not [System.IO.File]::Exists($path) -or $context.Request.HttpMethod -notin 'GET', 'HEAD') {
                $response.StatusCode = 404
            } else {
                $bytes = [System.IO.File]::ReadAllBytes($path)
                $extension = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
                $response.ContentType = if ($types.ContainsKey($extension)) { $types[$extension] } else { 'application/octet-stream' }
                $response.ContentLength64 = $bytes.Length
                if ($context.Request.HttpMethod -eq 'GET') { $response.OutputStream.Write($bytes, 0, $bytes.Length) }
            }
        } catch {
            $response.StatusCode = 500
        } finally {
            $response.Close()
        }
    }
} finally {
    $listener.Stop()
}
