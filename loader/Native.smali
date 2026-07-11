.class public Lplongdev/HyperGuardPro/Loader;
.super Landroid/app/Application;

# direct methods
.method static constructor <clinit>()V
    .registers 0

    invoke-static {}, Lplongdev/HyperGuardPro/Loader;->loadLibraries()V

    return-void
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method public onCreate()V
    .registers 1
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    
    # Kích hoạt bảo vệ UI (Hardcoded)
    invoke-static {p0}, Lplongdev/HyperGuardPro/UIHijackingDetect;->init(Landroid/app/Application;)V
    
    return-void
.end method

# Logic load lib sẽ được Python thay thế hoàn toàn tùy theo chế độ (Unified/Split)
.method private static loadLibraries()V
    .registers 0
    return-void
.end method

# Tên hàm native sẽ được Python cập nhật khớp với lib_name
.method public static final native PLongDeveloper_HyperGuard_Pro()V
.end method
