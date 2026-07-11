.class public Lplongdev/HyperGuardPro/UIHijackingDetect;
.super Ljava/lang/Object;
.source "UIHijackingDetect.java"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;
.implements Ljava/lang/Runnable;


# instance fields
.field private handler:Landroid/os/Handler;

.field private runnable:Ljava/lang/Runnable;

.field private final activityRef:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "Landroid/app/Activity;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .registers 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    iput-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->handler:Landroid/os/Handler;

    const/4 v0, 0x0

    iput-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->activityRef:Ljava/lang/ref/WeakReference;

    return-void
.end method

.method public constructor <init>(Landroid/app/Activity;)V
    .registers 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->activityRef:Ljava/lang/ref/WeakReference;

    return-void
.end method

.method public static init(Landroid/app/Application;)V
    .registers 2

    new-instance v0, Lplongdev/HyperGuardPro/UIHijackingDetect;

    invoke-direct {v0}, Lplongdev/HyperGuardPro/UIHijackingDetect;-><init>()V

    invoke-virtual {p0, v0}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    return-void
.end method

.method private a()Ljava/lang/String;
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

.method private a(Landroid/app/Activity;)Ljava/lang/String;
    .registers 4

    invoke-direct {p0}, Lplongdev/HyperGuardPro/UIHijackingDetect;->a()Ljava/lang/String;

    move-result-object v0

    const-string v1, "vi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_msg_zh

    const-string v0, "\u1ee8ng d\u1ee5ng \u0111\u00e3 được chuy\u1ec3n xu\u1ed1ng n\u1ec1n"

    return-object v0

    :cond_msg_zh
    const-string v1, "zh"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_msg_en

    const-string v0, "\u5e94\u7528\u5df2\u88ab\u5207\u6362\u81f3\u540e\u53f0"

    return-object v0

    :cond_msg_en
    const-string v0, "App has been switched to background"

    :goto_e
    return-object v0
.end method


# virtual methods
.method public run()V
    .registers 3

    iget-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->activityRef:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/Activity;

    if-eqz v0, :cond_16

    invoke-virtual {v0}, Landroid/app/Activity;->isFinishing()Z

    move-result v1

    if-nez v1, :cond_16

    invoke-virtual {v0}, Landroid/app/Activity;->isDestroyed()Z

    move-result v1

    if-eqz v1, :cond_1e

    :cond_16
    const-string v0, "[HyperGuard]"

    const-string v1, "[sub] The activity pointer has been destroyed."

    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    :goto_1d
    return-void

    :cond_1e
    invoke-virtual {p0, v0}, Lplongdev/HyperGuardPro/UIHijackingDetect;->showUIHijackingWarningInfo(Landroid/app/Activity;)V

    goto :goto_1d
.end method

.method public showUIHijackingWarningInfo(Landroid/app/Activity;)V
    .registers 5

    invoke-virtual {p1}, Landroid/app/Activity;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    invoke-direct {p0, p1}, Lplongdev/HyperGuardPro/UIHijackingDetect;->a(Landroid/app/Activity;)Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v0

    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    return-void
.end method

.method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .registers 3

    # Check Anti-Crack as soon as any activity is created
    invoke-static {p1}, Lplongdev/HyperGuardPro/HyperGuard;->AntiCrack(Landroid/app/Activity;)V

    return-void
.end method

.method public onActivityStarted(Landroid/app/Activity;)V
    .registers 2
    return-void
.end method

.method public onActivityResumed(Landroid/app/Activity;)V
    .registers 4

    iget-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->runnable:Ljava/lang/Runnable;

    if-eqz v0, :cond_e

    iget-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->handler:Landroid/os/Handler;

    iget-object v1, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->runnable:Ljava/lang/Runnable;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    const/4 v0, 0x0

    iput-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->runnable:Ljava/lang/Runnable;

    :cond_e
    return-void
.end method

.method public onActivityPaused(Landroid/app/Activity;)V
    .registers 6

    if-eqz p1, :cond_e

    invoke-virtual {p1}, Landroid/app/Activity;->isFinishing()Z

    move-result v0

    if-nez v0, :cond_e

    invoke-virtual {p1}, Landroid/app/Activity;->isDestroyed()Z

    move-result v0

    if-eqz v0, :cond_f

    :cond_e
    :goto_e
    return-void

    :cond_f
    new-instance v0, Lplongdev/HyperGuardPro/UIHijackingDetect;

    invoke-direct {v0, p1}, Lplongdev/HyperGuardPro/UIHijackingDetect;-><init>(Landroid/app/Activity;)V

    iput-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->runnable:Ljava/lang/Runnable;

    iget-object v0, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->handler:Landroid/os/Handler;

    iget-object v1, p0, Lplongdev/HyperGuardPro/UIHijackingDetect;->runnable:Ljava/lang/Runnable;

    const-wide/16 v2, 0x3e8

    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    goto :goto_e
.end method

.method public onActivityStopped(Landroid/app/Activity;)V
    .registers 2
    return-void
.end method

.method public onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .registers 3
    return-void
.end method

.method public onActivityDestroyed(Landroid/app/Activity;)V
    .registers 2
    return-void
.end method
