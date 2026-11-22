# 编译 CulvertProxy 的 Winsock 注入 DLL（x64）。
# 依赖 Visual Studio 2022 的 MSVC 与 Windows SDK；仅构建原生组件。
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # 同时编译端到端诊断用的原生探针。
    [switch]$WithProbe
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $root 'bin\x64'
$objDir = Join-Path $root 'obj\x64'
New-Item -ItemType Directory -Force -Path $outDir, $objDir | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw '未找到 vswhere.exe，请安装 Visual Studio 2022 并勾选 C++ 桌面开发工作负载。'
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw '未找到带 MSVC x64 工具的 Visual Studio 2022 安装。'
}

$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    throw "未找到 vcvars64.bat：$vcvars"
}

$minhook = Join-Path $root 'third_party\minhook'
$sources = @(
    (Join-Path $root 'src\CulvertHook.c'),
    (Join-Path $minhook 'src\hook.c'),
    (Join-Path $minhook 'src\buffer.c'),
    (Join-Path $minhook 'src\trampoline.c'),
    (Join-Path $minhook 'src\hde\hde64.c')
)
foreach ($source in $sources) {
    if (-not (Test-Path $source)) {
        throw "缺少源文件：$source"
    }
}

$optimization = if ($Configuration -eq 'Debug') { '/Od /Zi' } else { '/O2 /Zi' }
$quotedSources = ($sources | ForEach-Object { '"' + $_ + '"' }) -join ' '
$dll = Join-Path $outDir 'CulvertHook.dll'
$arguments = @(
    'cl.exe', '/nologo', '/LD', '/std:c11', '/MT', '/W3', '/EHsc', '/utf-8',
    $optimization, ('/Fd"' + (Join-Path $objDir 'CulvertHookCompile.pdb') + '"'),
    '/D_CRT_SECURE_NO_WARNINGS', '/DWIN32_LEAN_AND_MEAN',
    '/D_WIN32_WINNT=0x0A00', '/DUNICODE', '/D_UNICODE',
    ('/I"' + (Join-Path $minhook 'include') + '"'),
    ('/I"' + $minhook + '"'), ('/I"' + (Join-Path $minhook 'src') + '"'),
    ('/Fo"' + $objDir + '\\"'),
    $quotedSources,
    ('/Fe"' + $dll + '"'),
    '/link', '/INCREMENTAL:NO', '/DEBUG', '/DYNAMICBASE', '/NXCOMPAT',
    'ws2_32.lib', 'advapi32.lib'
) -join ' '

Write-Host "编译 x64 CulvertHook.dll ($Configuration)..." -ForegroundColor Cyan
$command = "call `"$vcvars`" >nul && $arguments"
& "$env:ComSpec" /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "CulvertHook.dll 编译失败，退出码 $LASTEXITCODE。"
}

$pdb = Join-Path $outDir 'CulvertHook.pdb'
if (Test-Path $pdb) {
    Write-Host "已生成：$dll (+pdb)" -ForegroundColor Green
} else {
    Write-Host "已生成：$dll" -ForegroundColor Green
}

if ($WithProbe) {
    $probeSource = Join-Path $root 'tools\probe.c'
    $probeExe = Join-Path $outDir 'probe.exe'
    Write-Host '编译 x64 probe.exe...' -ForegroundColor Cyan
    $probeArguments = @(
        'cl.exe', '/nologo', '/std:c11', '/MT', '/W3', '/utf-8', $optimization,
        ('/Fd"' + (Join-Path $objDir 'probe.pdb') + '"'),
        '/D_CRT_SECURE_NO_WARNINGS', '/DWIN32_LEAN_AND_MEAN', '/D_WIN32_WINNT=0x0A00',
        ('/Fo"' + $objDir + '\\"'),
        ('"' + $probeSource + '"'),
        ('/Fe"' + $probeExe + '"'),
        '/link', '/INCREMENTAL:NO', 'ws2_32.lib'
    ) -join ' '
    & "$env:ComSpec" /d /s /c "call `"$vcvars`" >nul && $probeArguments"
    if ($LASTEXITCODE -ne 0) {
        throw "probe.exe 编译失败，退出码 $LASTEXITCODE。"
    }

    Write-Host "已生成：$probeExe" -ForegroundColor Green
}
