# FridaGadget Loader

针对未越狱的iOS设备，使用FridaGadget进行动态分析和调试。特别是针对启动时会检测Frida的应用，使用此工具可以绕过检测。

## 下载Gadget

https://github.com/frida/frida/releases

建议始终下载最新版。iOS 26 至少使用 `17.15.3`，该版本修复了 Darwin
Interceptor 初始化时可能因模块注册表尚未就绪而崩溃的问题；本仓库原有的
`17.14.1` 不满足此要求，必须替换。当前可使用 `17.16.1`：

https://github.com/frida/frida/releases/download/17.16.1/frida-gadget-17.16.1-ios-universal.dylib.gz

下载、解压后重命名为 `frigad.dylib`。Mac 上的 `frida` Python 包、
`frida-tools` 与 Gadget 也建议同时升级，并尽量保持 Frida 核心版本一致。

## 编译指令

```bash
xcrun --sdk iphoneos clang \
  -dynamiclib \
  -arch arm64 \
  -std=c11 \
  -Wall -Wextra -Werror \
  -miphoneos-version-min=13.0 \
  -Wl,-install_name,@rpath/ios_loader.dylib \
  ios_loader.c \
  -o ios_loader.dylib
```

默认等待 Xcode 调试器 600 秒，每 250 ms 检测一次。可在编译时覆盖参数，例如
无限等待：

```bash
xcrun --sdk iphoneos clang \
  -dynamiclib -arch arm64 -std=c11 -Wall -Wextra -Werror \
  -miphoneos-version-min=13.0 \
  -DLOADER_WAIT_TIMEOUT_SECONDS=0 \
  -Wl,-install_name,@rpath/ios_loader.dylib \
  ios_loader.c -o ios_loader.dylib
```

## 使用方法

1. 下载安装 `Sideloadly`(https://sideloadly.io/)，用于将 `ios_loader.dylib` 注入到 iOS 应用中。
2. 解压ipa文件，找到 `Payload` 文件夹，将 `frigad.dylib` 放入 `Payload/xxx.app/Frameworks` 目录下; 将`frigad.config` 放入 `Payload/xxx.app/` 目录下。
3. 使用 `Sideloadly` 将修改后的ipa文件安装到iOS设备上：
   - 打开 `Sideloadly`，选择修改后的ipa文件。
   - 选择你的iOS设备。
   - Apple ID登录。
   - 勾选 `Inject dylib` 选项，并选择 `ios_loader.dylib`。取消勾选`Cydia Substrate`选项。
   - 点击 `Start` 按钮进行安装。

## 运行app

1. 安装完成后，在iOS设备上找到已安装的应用并打开。
2. 使用 Xcode 附加到 App 进程。首次 Continue 前，在 Xcode 的 LLDB 控制台
   导入本仓库的 page-plan 处理脚本（必须使用 Mac 上的绝对路径）：

   ```lldb
   command script import /absolute/path/to/frigad_lldb.py
   ```

   看到 `[FrigadLLDB] page-plan stop-hook installed` 后点击 Continue。loader
   会确认调试状态稳定后，在 App 主线程加载 Gadget；Xcode 控制台中可用
   `FrigadLoader` 过滤 loader 日志。
3. 测试frida是否注入成功，可以在终端中运行以下命令：

```bash
frida-ps -H <设备IP地址:端口> -n Gadget
```

能进入Frida REPL后，即表示Frida注入成功。

## iOS 26 的 page-plan 断点

iOS 26 的 debugger mapping 强制策略下，Frida Gadget 会主动执行
`brk #1337`，通过 x4/x5 向 Frida 自己的 jailed-iOS LLDB 注入器提交
page-plan。直接用 Xcode 加载 Gadget 时，Xcode 不认识该协议，只会显示
`EXC_BREAKPOINT` 并停在 `frigad.dylib` 的构造函数中。

`frigad_lldb.py` 会识别 x1、x2 和 x3 中的 Frida magic/action，读取 page-plan，
通过 LLDB 写回目标页面，然后设置 x0 与 pc 并自动继续。其他普通断点不会被
自动忽略。

M4 等较新的 SoC 对调试器映射要求更严格：即使是刚分配的匿名代码页，第一次
取指时也可能以 `EXC_BAD_ACCESS (code=50, ...)` 停止。`50` 是 XNU 的
`KERN_CODESIGN_ERROR`，不是普通野指针或 PAC 错误。脚本会在故障地址等于 PC
时把该页的最后一个字节原样写回，并自动继续，以补偿 Frida 偶发漏出
page-plan 的页面；数据访问引起的 code-sign 错误不会被自动处理。每次
page-plan 日志也会打印页面范围，便于确认故障页之前是否已提交。

如果导入脚本前已经停在以下位置：

```text
stop reason = EXC_BREAKPOINT
frigad.dylib`___lldb_unnamed_symbol... + ...
```

在 LLDB 控制台执行：

```lldb
command script import /absolute/path/to/frigad_lldb.py
frigad-page-plan
continue
```

若自动兜底被禁用或需要手动重试，可在 code=50 的停止点执行：

```lldb
frigad-codesign-page
continue
```

也可显式指定故障地址和页大小，例如：

```lldb
frigad-codesign-page 0x143b9c200 0x4000
continue
```

真机 iOS 默认页大小为 `0x4000`。手动命令也接受页大小参数，例如模拟器需要
使用 4 KB 页时可执行 `frigad-page-plan 0x1000`；本项目的 iOS 26 真机流程
无需修改默认值。

## 注意事项

- xcode调试的目的是为了拿到修改内存权限，方便Frida进行动态分析和调试。
- frida脚本里应用名称固定为 `Gadget`，请勿修改。
- `frigad.config` 必须与 Gadget 的基名一致，并放在 App 根目录；当前
  `frigad.dylib` 对应 `frigad.config`。Gadget 位于 `Frameworks` 时会按官方
  规则回退到父目录查找配置。
- iOS 26 上不要继续使用仓库原有的 `frigad.dylib` 17.14.1。如果崩溃日志的
  调用栈包含 `gum_interceptor`、module registry 或 libdyld，先替换为最新
  Gadget，而不是继续调整 loader 的等待时间。
- iOS 26 上即使使用 17.16.1，当前这种“Xcode 附加后由 App 内部 `dlopen`”的
  加载方式仍必须导入 `frigad_lldb.py`，因为只有 Frida 自己的注入器原生处理
  page-plan 协议。
- 若日志为 `DYLD 1 Library missing`、`code signature invalid`，需要重新签名
  `ios_loader.dylib`、`frigad.dylib` 和最终 App；这不是 loader 代码问题。
- 只有在不需要 `Interceptor` 的安全诊断模式下，才考虑在配置根节点加入
  `"code_signing": "required"`。该模式会禁用 Interceptor，不能作为常规
  Hook 配置使用。
