#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define DEVICE_NAME "myfirewall"
#define CLASS_NAME "firewall"

static struct class *firewall_class = NULL;
static struct device *firewall_device = NULL;
static int major_number;
static struct nf_hook_ops nfho;
static int blocked_port = 0;  // ブロックするポート番号

// パケットフック関数
static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr *tcp_header;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);

        // 動的に設定されたポート番号のパケットをブロック
        if (ntohs(tcp_header->dest) == blocked_port) {
            printk(KERN_INFO "Dropping packet to port %d\n", blocked_port);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// デバイスファイルへの書き込みをハンドリングする関数
static ssize_t firewall_write(struct file *file, const char __user *buffer,
                              size_t len, loff_t *offset) {
    char buf[256];
    int port;

    if (len > 255) return -EINVAL;
    if (copy_from_user(buf, buffer, len)) return -EFAULT;

    buf[len] = '\0';

    // 書き込まれた内容を解析してポート番号を設定
    if (sscanf(buf, "block %d", &port) == 1) {
        blocked_port = port;
        printk(KERN_INFO "Setting firewall to block port %d\n", blocked_port);
    }

    return len;
}

// ファイルオペレーション構造体の設定
static struct file_operations fops = {
    .write = firewall_write,
};

// モジュール初期化関数
static int __init firewall_module_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register character device\n");
        return major_number;
    }

    firewall_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(firewall_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(firewall_class);
    }

    firewall_device = device_create(firewall_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(firewall_device)) {
        class_destroy(firewall_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(firewall_device);
    }

    // Netfilter フックの設定
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "Firewall module loaded with device /dev/%s\n", DEVICE_NAME);
    return 0;
}

// モジュール終了関数
static void __exit firewall_module_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);  // Netfilter フック解除
    device_destroy(firewall_class, MKDEV(major_number, 0));
    class_unregister(firewall_class);
    class_destroy(firewall_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Firewall module unloaded\n");
}

module_init(firewall_module_init);
module_exit(firewall_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("User");
MODULE_DESCRIPTION("Firewall Module with Dynamic Control");
