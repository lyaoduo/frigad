#include <stdio.h>
#include <syslog.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>

// 检测当前进程是否正在被调试（通过 sysctl 检测 p_flag）
static int is_debugger_attached(void) {
    int mib[4];
    struct kinfo_proc info;
    size_t size;

    // 初始化 kinfo_proc 结构体
    info.kp_proc.p_flag = 0;

    // 设置 MIB 参数以查询特定 PID 的进程信息
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid(); // 获取当前 App 的 PID

    size = sizeof(info);
    
    // 调用 sysctl 获取进程内核状态
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        // 判断 p_flag 是否包含 P_TRACED 标志（即是否有调试器附加）
        return ((info.kp_proc.p_flag & P_TRACED) != 0);
    }
    
    return 0; 
}

// 异步循环检测线程
void* loop_check_and_load_frida(void* arg) {
    syslog(LOG_ERR, "==== [Loader] 循环检测线程已启动，等待调试器挂载... ====");
    
    int max_attempts = 600; // 设置一个超时上限，比如最多等待 60 秒，防止线程永久挂起
    int attempts = 0;

    while (attempts < max_attempts) {
        attempts++;
        
        if (is_debugger_attached()) {
            syslog(LOG_ERR, "==== [SUCCESS] 检测到调试器已附加！正在激活 FridaGadget... ====");
            
            // 调试器已就绪，安全加载 Frida
            void* handle = dlopen("@executable_path/Frameworks/frigad.dylib", RTLD_NOW);
            
            if (handle) {
                syslog(LOG_ERR, "==== [SUCCESS] FridaGadget 动态加载成功！ ====");
            } else {
                syslog(LOG_ERR, "==== [ERROR] FridaGadget 加载失败: %s ====", dlerror());
            }
            
            // 成功加载后，必须跳出循环，结束线程
            break; 
        }
        
        // 如果没有检测到调试器，打印一条日志，并等待 1 秒后继续下一次检测
        syslog(LOG_ERR, "==== [Loader] 暂未检测到调试器，第 %d 次等待中... ====", attempts);
        sleep(1); 
    }

    if (attempts >= max_attempts) {
        syslog(LOG_ERR, "==== [Loader] 等待调试器超时（60秒），线程退出，放弃加载 Frida。 ====");
    }

    return NULL;
}

// 构造函数：App 启动时最先触发
__attribute__((constructor)) static void initialize() {
    pthread_t thread;
    // 创建一个独立的子线程去跑循环，千万不能阻塞 App 主线程，否则会引发看门狗（Watchdog）杀进程
    pthread_create(&thread, NULL, loop_check_and_load_frida, NULL);
    pthread_detach(thread);
}
