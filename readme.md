# FridaGadget Loader

针对未越狱的iOS设备，使用FridaGadget进行动态分析和调试。特别是针对启动时会检测Frida的应用，使用此工具可以绕过检测。

## 下载Gadget

https://github.com/frida/frida/releases

建议下载17.14.1版本

https://github.com/frida/frida/releases/download/17.14.1/frida-gadget-17.14.1-ios-universal.dylib.gz

下载后重命名为 `frigad.dylib`

## 编译指令

```bash
clang -shared -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch arm64 ios_loader.c -o ios_loader.dylib
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
2. 使用xcode对app进行调试。调试时，Frida会自动注入到应用中，你可以使用Frida的命令行工具或Python脚本进行动态分析和调试。
3. 测试frida是否注入成功，可以在终端中运行以下命令：

```bash
frida-ps -H <设备IP地址:端口> -n Gadget
```

能进入Frida REPL后，即表示Frida注入成功。

## 注意事项

- xcode调试的目的是为了拿到修改内存权限，方便Frida进行动态分析和调试。
- frida脚本里应用名称固定为 `Gadget`，请勿修改。
