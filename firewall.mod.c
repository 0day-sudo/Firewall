#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x4d271a65, "init_net" },
	{ 0x67086d2d, "__netlink_kernel_create" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x437457f3, "netlink_kernel_release" },
	{ 0xf46d5bf3, "mutex_lock" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0xf46d5bf3, "mutex_unlock" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0x4ac4312d, "kmalloc_caches" },
	{ 0x8d1d7639, "__kmalloc_cache_noprof" },
	{ 0xd272d446, "__fentry__" },
	{ 0xe8213e80, "_printk" },
	{ 0x70eca2ca, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x4d271a65,
	0x67086d2d,
	0xd272d446,
	0xd272d446,
	0x437457f3,
	0xf46d5bf3,
	0xcb8b6ec6,
	0xf46d5bf3,
	0xbd03ed67,
	0x4ac4312d,
	0x8d1d7639,
	0xd272d446,
	0xe8213e80,
	0x70eca2ca,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"init_net\0"
	"__netlink_kernel_create\0"
	"__x86_return_thunk\0"
	"__stack_chk_fail\0"
	"netlink_kernel_release\0"
	"mutex_lock\0"
	"kfree\0"
	"mutex_unlock\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"__fentry__\0"
	"_printk\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "DAEDF58212228718A7B892A");
