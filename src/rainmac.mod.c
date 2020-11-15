#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0x89e24b9c, "struct_module" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xe9bd5e87, "security_ops" },
	{ 0xb2630bb5, "__vm_enough_memory" },
	{ 0xabe77484, "securebits" },
	{ 0x89b301d4, "param_get_int" },
	{ 0xb694c524, "suid_dumpable" },
	{ 0x3d7c39ea, "_read_lock" },
	{ 0xab978df6, "malloc_sizes" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x1bcd461f, "_spin_lock" },
	{ 0x5d57df57, "remove_proc_entry" },
	{ 0x85df9b6c, "strsep" },
	{ 0x98bd6f46, "param_set_int" },
	{ 0x1d26aa98, "sprintf" },
	{ 0x6315b09, "proc_mkdir" },
	{ 0x1b7d4074, "printk" },
	{ 0x179ec4b8, "dcache_lock" },
	{ 0x7dceceac, "capable" },
	{ 0x4b05104f, "_write_lock" },
	{ 0x19070091, "kmem_cache_alloc" },
	{ 0xd5028665, "create_proc_entry" },
	{ 0x6989a769, "vsnprintf" },
	{ 0xb85ab97a, "kmem_cache_zalloc" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0xf2a644fb, "copy_from_user" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "2BC3CCF9E19E53254D08541");
