package io.github.xalsace.qqdetectbypass;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.BatchFindMethodUsingStrings;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.MethodDataList;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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

    public static void hook(ClassLoader cl) {
        try (DexKitBridge bridge = DexKitBridge.Companion.create(cl, false)) {
            // 在 com.tencent.mobileqq.channel 包内按字符串引用定位上报方法
            BatchFindMethodUsingStrings query = new BatchFindMethodUsingStrings();
            query.searchPackages(Collections.singletonList("com.tencent.mobileqq.channel"));
            Map<String, java.util.Collection<String>> groups = new HashMap<>();
            groups.put("sso", Collections.singletonList(SSO));
            query.groups(groups);

            Map<String, MethodDataList> result = bridge.batchFindMethodUsingStrings(query);
            int hit = 0;
            for (MethodDataList list : result.values()) {
                for (MethodData md : list) {
                    try {
                        Method m = md.getMethodInstance(cl);
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
}