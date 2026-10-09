param([string]$OutputDirectory = 'dist')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.8 est nécessaire.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Add-Type -AssemblyName System.Drawing
$bitmap = New-Object System.Drawing.Bitmap 64,64
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = 'AntiAlias'
$graphics.Clear([System.Drawing.Color]::FromArgb(11,18,32))
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(132,171,255)),5
$graphics.DrawArc($pen,21,10,22,27,180,180)
$brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(132,171,255))
$graphics.FillRectangle($brush,16,27,32,26)
$graphics.FillEllipse([System.Drawing.Brushes]::MidnightBlue,29,34,6,8)
$graphics.FillRectangle([System.Drawing.Brushes]::MidnightBlue,30,40,4,6)
$icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())
$iconStream = [System.IO.File]::Create((Join-Path $PSScriptRoot 'app.ico'))
$icon.Save($iconStream)
$iconStream.Dispose()
$graphics.Dispose()
$bitmap.Dispose()
$pen.Dispose()
$brush.Dispose()
$references = @('System.dll','System.Core.dll','System.Runtime.Serialization.dll','System.Xaml.dll','WPF\WindowsBase.dll','WPF\PresentationCore.dll','WPF\PresentationFramework.dll')
$arguments = @('/nologo','/target:winexe','/platform:x64','/optimize+','/utf8output',('/out:' + (Join-Path $OutputDirectory 'CompanionPasswords.exe')),'/win32manifest:app.manifest','/win32icon:app.ico','/resource:Theme.xaml,Theme.xaml','/resource:app.ico,app.ico')
foreach ($reference in $references) { $arguments += ('/reference:' + (Join-Path $framework $reference)) }
$arguments += @('AssemblyInfo.cs','Core.cs','App.cs','Tests.cs')
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw 'Échec de la compilation.' }
Copy-Item -LiteralPath 'CompanionPasswords.exe.config' -Destination (Join-Path $OutputDirectory 'CompanionPasswords.exe.config') -Force
if (Test-Path -LiteralPath 'README.md') { Copy-Item -LiteralPath 'README.md' -Destination (Join-Path $OutputDirectory 'LISEZ-MOI.md') -Force }
Write-Output ('Compile : ' + (Join-Path $OutputDirectory 'CompanionPasswords.exe'))
