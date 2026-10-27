package io.github.xalsace.qqdetectbypass;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.BatchFindMethodUsingStrings;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.ClassData;

import java.lang.reflect.Method;
import java.util.List;

/**
 * 对应 QQNT-Patcher security_rules.py 第 1 处：
 * 阻断 com.tencent.mobileqq.channel.ChannelReport 里发送
 * trpc.o3.report.Report.SsoEventReport 通道风控上报的方法。
 *
 * 用 DexKit 2.0.0 的 BatchFindMethodUsingStrings 按字符串常量引用定位
 * （版本无关：混淆会改类名方法名，但方法体里引用的 SSO 命令名字符串基本不动）。
 * 命中即 setResult(null)，让上报不发出去，服务端拿不到本次环境快照。
 */
public class BlockSsoEventReport {
    private static final String SSO = "trpc.o3.report.Report.SsoEventReport";
    private static final String CHANNEL_REPORT = "com.tencent.mobileqq.channel.ChannelReport";

    public static void hook(ClassLoader cl) {
        // 先用 findClass 定位 ChannelReport 类，再在类内按字符串批量找方法
        ClassData targetClass = findChannelReport(cl);
        if (targetClass == null) {
            XposedBridge.log("[QQDetectBypass] ChannelReport class not found, skip SsoEventReport");
            return;
        }
        try (DexKitBridge bridge = DexKitBridge.Companion.create(cl, false)) {
            BatchFindMethodUsingStrings query = new BatchFindMethodUsingStrings()
                    .addString(SSO)
                    .searchInClasses(java.util.Collections.singletonList(targetClass));
            java.util.Map<String, List<MethodData>> result = bridge.batchFindMethodUsingStrings(query);
            int hit = 0;
            for (List<MethodData> methods : result.values()) {
                for (MethodData md : methods) {
                    try {
                        Method m = md.getMethodInstance();
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) {
                                p.setResult(null);
                            }
                        });
                        hit++;
                    } catch (Throwable e) {
                        XposedBridge.log("[QQDetectBypass] SsoEventReport hook one fail: " + e);
                    }
                }
            }
            XposedBridge.log("[QQDetectBypass] SsoEventReport blocked: " + hit);
        } catch (Throwable t) {
            XposedBridge.log("[QQDetectBypass] SsoEventReport fail: " + t);
        }
    }

    private static ClassData findChannelReport(ClassLoader cl) {
        try (DexKitBridge bridge = DexKitBridge.Companion.create(cl, false)) {
            FindClass fc = new FindClass().searchClasses(
                    java.util.Collections.singletonList(CHANNEL_REPORT));
            List<ClassData> list = bridge.findClass(fc);
            return list.isEmpty() ? null : list.get(0);
        } catch (Throwable t) {
            XposedBridge.log("[QQDetectBypass] findChannelReport fail: " + t);
            return null;
        }
    }
}