package io.github.xalsace.qqdetectbypass;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.XposedBridge;

public class HookEntry implements IXposedHookLoadPackage {
    private static final String TAG = "QQDetectBypass";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpp) {
        if (!"com.tencent.mobileqq".equals(lpp.packageName)) return;
        XposedBridge.log("[" + TAG + "] attach " + lpp.packageName);
        BlockSsoEventReport.hook(lpp.classLoader);   // 拦风控上报（trpc.o3.report.Report.SsoEventReport）
        BlockBeaconPrivacy.hook(lpp.classLoader);    // 掏空硬件指纹收集（setBeaconPrivacyInfo）
    }
}