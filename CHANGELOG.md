# 变更记录

版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)：主版本号用于不兼容的接口或行为变更，次版本号用于向下兼容的功能，修订号用于向下兼容的修正。

## [1.0.1] — 未发布

### 变更

- **标准构建剥离直连系统调用层。** `Syscall`、`VirtualAlloc` / `VirtualProtect` 导入、`RtlExitUserProcess`、远程线程与 APC 投递、`NtGetNextThread` 线程遍历全部改为条件编译，仅在 `-p:EnableAdvanced=true` 时参与编译。标准发布件中相关导入名与 syscall 桩字节序列零命中。
- **分层结束进程在标准构建下收敛为标准路径**：提权 → `TerminateProcess`；高级路径在日志中标注「跳过」而非报错。
- **设置面板的高级终止开关在标准构建下置灰**，并说明原因，避免"开关可点但无效"的困惑。
- **新增 MSI 安装包**：每用户安装到 `%LOCALAPPDATA%\Programs\MemScope`，安装过程不请求管理员权限，含开始菜单快捷方式与卸载条目。
- **新增构建校验脚本** `scripts/verify-standard-build.ps1`，把「发布件不得含直连系统调用与远程执行特征」固化为可执行断言，CI 与本地共用。
- **新增 CI 工作流**：Windows 环境双配置构建 + 校验 + 产物归档。

### 修复

- 模块提取产物偶发「文件正被另一个进程使用」：改为先写 `.part` 再原子改名，并对实时防护的短暂占用做指数退避重试。
- 后台哈希任务可能在缓冲区解固定后读到已搬迁内存：改为在任务完成后释放 `GCHandle`。
- 大于 64 MB 的模块不再计算磁盘原件哈希，改为整块内容比对，避免关键路径被哈希拖长。

## [1.0.0] — 2026-11-22

首个公开版本。

- 进程 / 模块 / 虚拟内存区域 / 文件句柄实时观测，浅色与深色双主题热切换
- 模块运行时映像还原为结构合法的 PE 文件，逐节与磁盘原件比对
- 分层结束进程：标准 `TerminateProcess` 路径 + 可选的高级路径
- 快照导出（CSV / JSON）、无界面模块提取、引擎基准
- 343 MB 模块关键路径中位 494 ms，358,196,787 字节比对零差异

[1.0.1]: https://github.com/FuYuHang123-bot/DUMP-root/compare/v1.0.0...main
[1.0.0]: https://github.com/FuYuHang123-bot/DUMP-root/releases/tag/v1.0.0
