.class public Lplongdev/HyperGuardPro/HyperGuard;
.super Ljava/lang/Object;

# interfaces
.implements Ljava/lang/Runnable;

# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method private static a()Ljava/lang/String;
    .registers 2

    :try_start_0
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v0

    iget-object v0, v0, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    invoke-virtual {v0}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_d} :catch_f

    move-result-object v0

    :goto_e
    return-object v0

    :catch_f
    move-exception v0

    const-string v0, "en"

    goto :goto_e
.end method

.method private static a(Landroid/app/Activity;)Ljava/lang/String;
    .registers 4

    invoke-static {}, Lplongdev/HyperGuardPro/HyperGuard;->a()Ljava/lang/String;

    move-result-object v0

    const-string v1, "vi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_msg_zh

    const-string v0, "\u1ee8ng d\u1ee5ng \u0111\u00e3 b\u1ecb s\u1eeda \u0111\u1ed5i v\u00e0 s\u1eafp tho\u00e1t ra..."

    return-object v0

    :cond_msg_zh
    const-string v1, "zh"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_msg_en

    const-string v0, "\u5e94\u7528\u5df2\u88ab\u4fee\u6539\uff0c\u5373\u5c06\u9000\u51fa..."

    return-object v0

    :cond_msg_en
    const-string v0, "App has been modified and will exit soon..."

    return-object v0
.end method

.method public static AntiCrack(Landroid/app/Activity;)V
    .registers 7

    # 1. Kiểm tra Package Name ngay lập tức
    invoke-virtual {p0}, Landroid/app/Activity;->getPackageName()Ljava/lang/String;
    move-result-object v0

    const-string v1, "PACKAGE_NAME_PLACEHOLDER"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0
    if-eqz v0, :cond_safe

    return-void

    :cond_safe
    # 2. CHẶN ĐIỀU KHIỂN & HIỆN MÀN TRẮNG CỰC ĐOAN
    # Sử dụng DecorView để đè lên toàn bộ kể cả ActionBar/StatusBar
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;
    move-result-object v0
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;
    move-result-object v0
    check-cast v0, Landroid/view/ViewGroup;

    # Tạo màn hình trắng
    new-instance v1, Landroid/view/View;
    invoke-direct {v1, p0}, Landroid/view/View;-><init>(Landroid/content/Context;)V
    const/4 v2, -0x1
    invoke-virtual {v1, v2}, Landroid/view/View;->setBackgroundColor(I)V
    
    # Khóa tương tác bằng cách chiếm quyền focus và click
    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/view/View;->setClickable(Z)V
    invoke-virtual {v1, v2}, Landroid/view/View;->setFocusable(Z)V
    invoke-virtual {v1, v2}, Landroid/view/View;->setFocusableInTouchMode(Z)V

    # Layout Full Screen
    new-instance v3, Landroid/view/ViewGroup$LayoutParams;
    const/4 v4, -0x1
    invoke-direct {v3, v4, v4}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    # Thêm trực tiếp vào DecorView
    invoke-virtual {v0, v1, v3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    # 3. Hiện cảnh báo đa ngôn ngữ
    invoke-static {p0}, Lplongdev/HyperGuardPro/HyperGuard;->a(Landroid/app/Activity;)Ljava/lang/String;
    move-result-object v0
    invoke-static {p0, v0, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
    move-result-object v0
    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    # 4. Thoát ứng dụng sau 2s
    new-instance v0, Landroid/os/Handler;
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;
    move-result-object v1
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance v1, Lplongdev/HyperGuardPro/HyperGuard;

    invoke-direct {v1}, Lplongdev/HyperGuardPro/HyperGuard;-><init>()V

    const-wide/16 v2, 0x7d0
    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    return-void
.end method


# virtual methods
.method public run()V
    .registers 2

    # Kill process ngay lập tức để không thể bypass
    invoke-static {}, Landroid/os/Process;->myPid()I
    move-result v0
    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V

    const/4 v0, 0x0
    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void
.end method
