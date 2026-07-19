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
2. 使用 Xcode 附加到 App 进程。如果 Xcode 附加后暂停在断点处，先点击
   Continue；loader 会确认调试状态稳定后，在 App 主线程加载 Gadget。
   Xcode 控制台中可用 `FrigadLoader` 过滤加载日志。
3. 测试frida是否注入成功，可以在终端中运行以下命令：

```bash
frida-ps -H <设备IP地址:端口> -n Gadget
```

能进入Frida REPL后，即表示Frida注入成功。

## 注意事项

- xcode调试的目的是为了拿到修改内存权限，方便Frida进行动态分析和调试。
- frida脚本里应用名称固定为 `Gadget`，请勿修改。
- `frigad.config` 必须与 Gadget 的基名一致，并放在 App 根目录；当前
  `frigad.dylib` 对应 `frigad.config`。Gadget 位于 `Frameworks` 时会按官方
  规则回退到父目录查找配置。
- iOS 26 上不要继续使用仓库原有的 `frigad.dylib` 17.14.1。如果崩溃日志的
  调用栈包含 `gum_interceptor`、module registry 或 libdyld，先替换为最新
  Gadget，而不是继续调整 loader 的等待时间。
- 若日志为 `DYLD 1 Library missing`、`code signature invalid`，需要重新签名
  `ios_loader.dylib`、`frigad.dylib` 和最终 App；这不是 loader 代码问题。
- 只有在不需要 `Interceptor` 的安全诊断模式下，才考虑在配置根节点加入
  `"code_signing": "required"`。该模式会禁用 Interceptor，不能作为常规
  Hook 配置使用。
