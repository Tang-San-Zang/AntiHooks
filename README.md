# AntiHooks
一种枚举进程的方式，可以无视很多应用层hook及驱动层hook

开发原因：
我们通常使用NtQuerySystemInformation进行枚举进程。但是，一些调试器或者恶意进程，会在R3或R0层对这个API进行hook。导致该进程对我们进程而言是隐藏的。所以，我想恢复枚举进程的正常运行。

成功原因：
这个姑且算漏洞吧。我们正向开发的时候，通常会对各种返回值进行判断，返回值是预期的，才会进行下一步，否则返回。例如NtQuerySystemInformation，我们会判断它的返回值是否为0，为0则代表成功。如果返回值为：0xC0000004,则代表缓冲区大小不够。

但是，即便缓冲区大小不够，系统依然会往缓冲区写入部分进程及线程的数据。既然有数据，我们就可以遍历进程线程。然而，一些反反调试插件，不管是R0层还是R3层，它们在碰到返回值为0xC0000004时，它们会直接放行。不会进行hook。比如ScyllaHook,TitanHide等等。

我们在sourcegraph上搜索NT_SUCCESS(status)，或者搜索 MyNtQuerySystemInformation,或者搜索 HookNtQuerySystemInformation等，能够发现，有太多太多的项目,在返回值不等于0的时候直接放弃hook。这就是我们的机会。

实现过程 ：
我们故意造成缓冲区不足。让NtQuerySystemInformation返回0xC0000004。这样我们能够正常枚举所有进程，但是hook函数会对我们放行。详细可以查看项目代码。

