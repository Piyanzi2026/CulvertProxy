# CulvertProxy 一键构建：原生 Hook → .NET 解决方案 → 测试 → 可选发布。
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipNative,
    [switch]$SkipTests,
    [switch]$Smoke,
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not $SkipNative) {
    & pwsh -NoProfile -File (Join-Path $root 'native\build.ps1') -Configuration $Configuration -WithProbe
    if ($LASTEXITCODE -ne 0) {
        throw '原生组件构建失败。'
    }
}

Write-Host "构建 .NET 解决方案 ($Configuration)..." -ForegroundColor Cyan
dotnet build (Join-Path $root 'CulvertProxy.sln') -c $Configuration
if ($LASTEXITCODE -ne 0) {
    throw '解决方案构建失败。'
}

if (-not $SkipTests) {
    Write-Host '运行测试...' -ForegroundColor Cyan
    dotnet test (Join-Path $root 'tests\Nexsteaduser.CulvertProxy.Tests\Nexsteaduser.CulvertProxy.Tests.csproj') -c $Configuration --no-build
    if ($LASTEXITCODE -ne 0) {
        throw '测试失败。'
    }
}

if ($Smoke) {
    Write-Host '运行注入端到端冒烟...' -ForegroundColor Cyan
    $smokeExe = Join-Path $root "tools\CulvertProxy.SmokeTest\bin\x64\$Configuration\net11.0-windows10.0.26100.0\win-x64\CulvertProxy.SmokeTest.exe"
    if (-not (Test-Path $smokeExe)) {
        $smokeExe = Join-Path $root "tools\CulvertProxy.SmokeTest\bin\$Configuration\net11.0-windows10.0.26100.0\win-x64\CulvertProxy.SmokeTest.exe"
    }

    if (-not (Test-Path $smokeExe)) {
        throw "未找到冒烟工具：$smokeExe"
    }

    $dotnetProbe = Join-Path $root "tools\DotnetProbe\bin\x64\$Configuration\net11.0-windows10.0.26100.0\win-x64\DotnetProbe.exe"
    if (-not (Test-Path $dotnetProbe)) {
        $dotnetProbe = Join-Path $root "tools\DotnetProbe\bin\$Configuration\net11.0-windows10.0.26100.0\win-x64\DotnetProbe.exe"
    }

    if (Test-Path $dotnetProbe) {
        & $smokeExe $dotnetProbe
    } else {
        & $smokeExe
    }

    if ($LASTEXITCODE -ne 0) {
        throw '冒烟测试失败。'
    }
}

if ($Publish) {
    $publishDir = Join-Path $root 'artifacts\publish\win-x64'
    if (Test-Path $publishDir) {
        Remove-Item $publishDir -Recurse -Force
    }

    Write-Host '发布自包含 WinUI3 应用...' -ForegroundColor Cyan
    dotnet publish (Join-Path $root 'src\Nexsteaduser.CulvertProxy.App\Nexsteaduser.CulvertProxy.App.csproj') `
        -c $Configuration -r win-x64 -p:Platform=x64 --self-contained true -o $publishDir
    if ($LASTEXITCODE -ne 0) {
        throw '发布失败。'
    }

    # WinUI 3 自包含发布在当前 SDK 下不会自动带上编译后的 XAML 资源，必须从构建输出补齐。
    $appOut = Join-Path $root "src\Nexsteaduser.CulvertProxy.App\bin\x64\$Configuration\net11.0-windows10.0.26100.0\win-x64"
    if (Test-Path $appOut) {
        Get-ChildItem $appOut -Recurse -File -Filter '*.xbf' | ForEach-Object {
            $relative = $_.FullName.Substring($appOut.Length + 1)
            $destination = Join-Path $publishDir $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item $_.FullName $destination -Force
        }

        $appPri = Join-Path $appOut 'CulvertProxy.pri'
        if (Test-Path $appPri) {
            Copy-Item $appPri $publishDir -Force
        }
    }

    Write-Host '发布自包含 CLI...' -ForegroundColor Cyan
    $cliDir = Join-Path $publishDir 'cli'
    dotnet publish (Join-Path $root 'src\Nexsteaduser.CulvertProxy.Cli\Nexsteaduser.CulvertProxy.Cli.csproj') `
        -c $Configuration -r win-x64 -p:Platform=x64 --self-contained true -o $cliDir
    if ($LASTEXITCODE -ne 0) {
        throw 'CLI 发布失败。'
    }

    Copy-Item (Join-Path $root 'README.md') $publishDir -Force
    Copy-Item (Join-Path $root 'THIRD-PARTY-NOTICES.md') $publishDir -Force
    Copy-Item (Join-Path $root 'LICENSE') $publishDir -Force
    Copy-Item (Join-Path $root 'NOTICE') $publishDir -Force
    Copy-Item (Join-Path $root 'docs') $publishDir -Recurse -Force

    # 发布包不带符号，减少体积；调试符号可由源码重新生成。
    Get-ChildItem $publishDir -Filter '*.pdb' -Recurse -File | Remove-Item -Force

    $zip = Join-Path $root 'artifacts\CulvertProxy-win-x64.zip'
    if (Test-Path $zip) {
        Remove-Item $zip -Force
    }

    Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $zip
    Write-Host "发布完成：$publishDir" -ForegroundColor Green
    Write-Host "压缩包：$zip" -ForegroundColor Green
}

Write-Host '构建完成。' -ForegroundColor Green
