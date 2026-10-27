package io.github.xalsace.qqdetectbypass;

import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 对应 QQNT-Patcher security_rules.py 第 2 处：
 * 掏空 com.tencent.mobileqq.statistics.QQBeaconReport.setBeaconPrivacyInfo()V
 * 灯塔 Beacon 是腾讯硬件/设备指纹收集通道，直接 return 让收集不到数据。
 */
public class BlockBeaconPrivacy {
    public static void hook(ClassLoader cl) {
        try {
            Class<?> cls = XposedHelpers.findClass(
                    "com.tencent.mobileqq.statistics.QQBeaconReport", cl);
            XposedHelpers.findAndHookMethod(cls, "setBeaconPrivacyInfo",
                    XC_MethodReplacement.returnConstant(null));
            XposedBridge.log("[QQDetectBypass] BeaconPrivacy stubbed OK");
        } catch (Throwable t) {
            XposedBridge.log("[QQDetectBypass] BeaconPrivacy fail: " + t);
        }
    }
}
