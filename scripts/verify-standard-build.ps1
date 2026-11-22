<#
.SYNOPSIS
    校验标准构建的发布件中不含直连系统调用与进程注入特征。

.DESCRIPTION
    标准构建（不带 -p:EnableAdvanced=true）用于对外发布与 MSI 打包。
    这类工具被安全软件标记，主要触发点不是"读了别的进程内存"——那属于工具的正常用途、
    也是调试器和进程浏览器的公共行为——而是"绕过用户态拦截 + 在别的进程里执行代码"
    这一套组合：自行解析系统调用号、构造 syscall 桩、申请可执行内存、远程创建线程、投递 APC。

    因此本脚本把上述动作对应的导入名与桩字节特征列为硬性禁止项，任何一项命中即返回非零退出码。
    标准 API（OpenProcess / ReadProcessMemory / TerminateProcess 等）不在禁止之列——
    删掉它们程序就没有功能了，且它们本身是 Windows 调试接口的公开用途。

.PARAMETER Path
    待校验的托管程序集。默认校验 dist 目录下的发布件，也可传入构建输出路径。

.EXAMPLE
    powershell -File scripts\verify-standard-build.ps1

.EXAMPLE
    powershell -File scripts\verify-standard-build.ps1 -Path MemScope\bin\Release\net10.0-windows\MemScope.dll
#>
[CmdletBinding()]
param(
    [string[]] $Path = @('dist\MemScope\MemScope.dll')
)

$ErrorActionPreference = 'Stop'
$failed = $false

# ---- 硬性禁止：直连系统调用 + 远程执行 ----
$forbidden = [ordered]@{
    'NtCreateThreadEx'      = '远程线程创建'
    'NtQueueApcThread'      = 'APC 投递'
    'NtGetNextThread'       = '线程遍历（APC 路径前置）'
    'RtlExitUserProcess'    = '远程退出例程'
    'WriteProcessMemory'    = '跨进程写入'
    'CreateRemoteThread'    = '远程线程创建（Win32）'
    'QueueUserAPC'          = 'APC 投递（Win32）'
    'SetThreadContext'      = '线程上下文改写'
    'Wow64SetThreadContext' = 'WOW64 线程上下文改写'
    'VirtualAllocEx'        = '跨进程内存分配'
    'VirtualProtectEx'      = '跨进程页权限修改'
    'VirtualAlloc'          = '可执行内存分配（syscall 桩载体）'
    'VirtualProtect'        = '页权限修改（syscall 桩载体）'
    'VirtualFree'           = '可执行内存释放（syscall 桩载体）'
}

# syscall 桩字节：mov r10, rcx / mov eax, imm32
$stubSignature = [byte[]] (0x4C, 0x8B, 0xD1, 0xB8)

function Find-ByteSequence {
    param([byte[]] $Haystack, [byte[]] $Needle)

    # 逐字节匹配，返回命中次数。不依赖编码类，Windows PowerShell 5.1 与 CI 上行为一致。
    $count = 0
    $limit = $Haystack.Length - $Needle.Length
    for ($i = 0; $i -le $limit; $i++) {
        if ($Haystack[$i] -ne $Needle[0]) { continue }
        $matched = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) { $matched = $false; break }
        }
        if ($matched) { $count++; $i += $Needle.Length - 1 }
    }
    return $count
}

function Read-PeSections {
    param([byte[]] $Bytes)

    # DOS 头 -> PE 头 -> 节表，返回节名与特性标志
    if ($Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return @() }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($peOffset -le 0 -or ($peOffset + 24) -ge $Bytes.Length) { return @() }
    if ([BitConverter]::ToUInt32($Bytes, $peOffset) -ne 0x00004550) { return @() }

    $sectionCount = [BitConverter]::ToUInt16($Bytes, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $peOffset + 20)
    $tableOffset = $peOffset + 24 + $optionalSize
    $result = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $o = $tableOffset + ($i * 40)
        if (($o + 40) -gt $Bytes.Length) { break }
        $name = [Text.Encoding]::ASCII.GetString($Bytes, $o, 8).TrimEnd([char]0)
        $result += [pscustomobject]@{
            Name        = $name
            Characteristics = [BitConverter]::ToUInt32($Bytes, $o + 36)
        }
    }
    return $result
}

foreach ($file in $Path) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Host "[错误] 文件不存在：$file" -ForegroundColor Red
        $failed = $true
        continue
    }

    $full = (Resolve-Path -LiteralPath $file).Path
    $bytes = [IO.File]::ReadAllBytes($full)
    Write-Host ""
    Write-Host "校验 $file（$($bytes.Length) 字节）" -ForegroundColor Cyan
    Write-Host ('-' * 62)

    # ---- 1. 禁止项扫描：托管字符串在元数据中以 UTF-16LE 存储，
    #        导入名同时可能以 ASCII 形式出现在非托管记录中，两种都查 ----
    $hits = 0
    foreach ($name in $forbidden.Keys) {
        $n = Find-ByteSequence -Haystack $bytes -Needle ([Text.Encoding]::Unicode.GetBytes($name))
        $m = Find-ByteSequence -Haystack $bytes -Needle ([Text.Encoding]::ASCII.GetBytes($name))
        if ($n -gt 0 -or $m -gt 0) {
            Write-Host ("  [命中] {0,-22} {1}  utf16={2} ascii={3}" -f $name, $forbidden[$name], $n, $m) -ForegroundColor Red
            $hits++
        }
    }
    if ($hits -eq 0) {
        Write-Host "  [通过] 直连系统调用与远程执行特征：0 命中" -ForegroundColor Green
    } else {
        Write-Host "  [失败] 共 $hits 项特征残留，该产物不得对外发布" -ForegroundColor Red
        $failed = $true
    }

    # ---- 2. syscall 桩字节序列 ----
    $stubHits = Find-ByteSequence -Haystack $bytes -Needle $stubSignature
    if ($stubHits -eq 0) {
        Write-Host "  [通过] syscall 桩字节序列（4C 8B D1 B8）：0 命中" -ForegroundColor Green
    } else {
        Write-Host "  [失败] syscall 桩字节序列命中 $stubHits 处" -ForegroundColor Red
        $failed = $true
    }

    # ---- 3. PE 节区不得同时可写可执行（RWX），也不得可执行且非常驻映像段 ----
    $sections = Read-PeSections -Bytes $bytes
    if ($sections.Count -eq 0) {
        Write-Host "  [跳过] 无法解析 PE 节区" -ForegroundColor Yellow
    } else {
        $rwx = @($sections | Where-Object { ($_.Characteristics -band 0x20000000) -and ($_.Characteristics -band 0x80000000) })
        if ($rwx.Count -eq 0) {
            Write-Host ("  [通过] PE 节区无可写可执行（{0} 个节：{1}）" -f $sections.Count, (($sections | ForEach-Object { $_.Name }) -join ' / ')) -ForegroundColor Green
        } else {
            Write-Host ("  [失败] 存在 RWX 节区：{0}" -f (($rwx | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Red
            $failed = $true
        }
    }

    # ---- 4. 签名状态仅作提示，不参与判定（自签名在 CI 上必然无效） ----
    $sig = Get-AuthenticodeSignature -LiteralPath $full
    Write-Host "  [提示] 签名状态：$($sig.Status)" -ForegroundColor DarkGray
}

Write-Host ""
if ($failed) {
    Write-Host "结果：不合格" -ForegroundColor Red
    exit 1
}
Write-Host "结果：通过 —— 发布件不含直连系统调用与远程执行特征" -ForegroundColor Green
exit 0
