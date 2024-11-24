// In mini-firewall.c

#include <linux/init.h> /* Needed for the macros */
#include <linux/kernel.h>
#include <linux/module.h> /* Needed by all modules */
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/hash.h>
#include <linux/inet.h>
MODULE_LICENSE("GPL");

#define OPTION_LEN 36
#define SHA256_DIGEST_SIZE 32
#define sign_interval 500
#define iphdrlen 56
#define length_of_HC 24
#define HC_input 16
unsigned char HC[SHA256_DIGEST_SIZE];
unsigned char hash[SHA256_DIGEST_SIZE];
unsigned int mark_flag = 0;
struct iphdr *old_iph;

// 定义模块参数
static int dest_port = 12301;            // 接收方的端口号
static int src_port = 12302;            //发送方的端口号
static char *ip_address = "192.168.3.102"; // 接收方的ip地址
//对满足上述三个要求的数据报，修改数据报结构，即加入新的字段。
// 注册模块参数
module_param(dest_port, int, 0644);
MODULE_PARM_DESC(dest_port, "TCP destination port");
module_param(src_port, int, 0644);
MODULE_PARM_DESC(src_port, "TCP destination port");
module_param(ip_address, charp, 0644);
MODULE_PARM_DESC(ip_address, "Source IP address");

// 计算SHA256哈希并返回每个字节的值的函数
void calculate_sha256(const unsigned char *data, size_t data_len, unsigned char *hash)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char *hash_alg = "sha256";
    int ret;

    // 使用内核提供的哈希算法
    tfm = crypto_alloc_shash(hash_alg, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Unable to allocate crypto context\n");
        return;
    }

    // 分配哈希描述符
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm),
                    GFP_KERNEL);
    if (!desc) {
        pr_err("Unable to allocate hash descriptor\n");
        crypto_free_shash(tfm);
        return;
    }

    desc->tfm = tfm;
    //desc->flags = 0;

    // 初始化哈希描述符
    ret = crypto_shash_init(desc);
    if (ret) {
        pr_err("Unable to initialize hash\n");
        kfree(desc);
        crypto_free_shash(tfm);
        return;
    }

    // 更新哈希值
    ret = crypto_shash_update(desc, data, data_len);
    if (ret) {
        pr_err("Unable to update hash\n");
        kfree(desc);
        crypto_free_shash(tfm);
        return;
    }

    // 完成哈希计算
    ret = crypto_shash_final(desc, hash);
    if (ret) {
        pr_err("Unable to finalize hash\n");
    }

    // 释放资源
    kfree(desc);
    crypto_free_shash(tfm);
}

typedef struct local_iphdr
{

    __u8 ihl : 4,
        version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
    __u8 options[OPTION_LEN];
} local_iphdr;

// 计算IP头部校验和函数
uint16_t calculate_ip_checksum(struct local_iphdr *iph)
{
    uint32_t sum = 0;
    int i;

    // 将整个IP头部作为16位字节对待，相加
    uint16_t *ptr = (uint16_t *)iph;
    for (i = 0; i < (iph->ihl * 4) / 2; ++i)
    {
        sum += *ptr++;
    }

    // 如果IP头部长度为奇数个16位字，最后一个字节需要额外处理
    if ((iph->ihl * 4) % 2)
    {
        sum += *((uint8_t *)ptr);
    }

    // 将溢出的部分加到低位
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 取反得到校验和
    return (uint16_t)~sum;
}

// 辅助函数：将二进制数据转换为十六进制字符串
void to_hex_string(const unsigned char *input, int length, char *output)
{
    int i;
    for (i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", input[i]);
    }
    output[length * 2] = '\0'; // 添加字符串结尾标志
}

// In mini-firewall.c
static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;   // IP header
    struct tcphdr *tcph; // TCP header
    
    // Find the start of TCP payload
    

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb); // retrieve the IP headers from the packet

    if (iph->protocol == IPPROTO_TCP)
    {

        tcph = tcp_hdr(skb);
        __be32 user_ip = in_aton(ip_address);
        int useless = 0;
        //if (tcph->dest == htons(11301) && tcph->source != htons(11303))
        if (tcph->dest == htons(dest_port) && iph->daddr == user_ip && tcph->source == htons(src_port))
        {

            memcpy(old_iph, iph, sizeof(struct iphdr));
            /* 计算IP头部长度 */
            int iphdr_len = iph->ihl * 4; // 以32位字为单位
            skb_pull(skb, iphdr_len);
            //pskb_expand_head扩展skb头部的空间
            if (skb_headroom(skb) < sizeof(struct local_iphdr)) {
                if (pskb_expand_head(skb, sizeof(struct local_iphdr) - skb_headroom(skb), 0, GFP_ATOMIC)) {
                printk(KERN_ERR "Failed to expand skb head\n");
                return NF_DROP;
                }
            }
            skb_push(skb, sizeof(struct local_iphdr));

            struct local_iphdr *new_iph = (struct local_iphdr *)skb->data;
            memset(new_iph, '\0', sizeof(struct local_iphdr));
            new_iph->version = old_iph->version;
            new_iph->ihl = old_iph->ihl + OPTION_LEN/ 4;
            new_iph->tos = old_iph->tos;
            new_iph->tot_len = ntohs(htons(old_iph->tot_len) + OPTION_LEN);
            new_iph->id = old_iph->id;
            new_iph->frag_off = old_iph->frag_off;
            new_iph->ttl = old_iph->ttl;
            new_iph->protocol = old_iph->protocol;
            new_iph->saddr = old_iph->saddr;
            new_iph->daddr = old_iph->daddr;

            // unsigned int tcphdr_len = tcph->doff * 4;

            // // 计算载荷的起始位置和长度
            // unsigned int payload_offset = iphdr_len + tcphdr_len;
            // unsigned int payload_len = skb->len - payload_offset;

            // // 分配缓冲区来存储载荷数据
            // unsigned char *payload = (unsigned char *)kmalloc(payload_len, GFP_KERNEL);
            // if (!payload)
            // {
            //     printk(KERN_ERR "Failed to allocate memory for payload\n");
            //     return NF_DROP;
            // }

            // // 复制载荷数据到缓冲区
            // memcpy(payload, skb->data + payload_offset, payload_len);

            // // 现在你可以处理或打印载荷数据
            // printk(KERN_INFO "Payload length: %u\n", payload_len);

            // // 示例：打印载荷的前64字节（如果有那么多字节）
            // unsigned int print_len = payload_len > 64 ? 64 : payload_len;
            // char hex_payload[print_len * 2 + 1];
            // to_hex_string(payload, print_len, hex_payload);
            // printk(KERN_INFO "Payload (first %u bytes): %s\n", print_len, hex_payload);

            // // 释放分配的缓冲区
            // kfree(payload);
           
            unsigned char message[120] = {'0'};
            int index = 0;
            int k;
    	    //拼接m+HC
            memcpy(message, skb->data + iphdrlen, HC_input);
            memcpy(message + HC_input, HC, length_of_HC);
    	    
            //sha256
    	    calculate_sha256(message, HC_input + length_of_HC, hash);
    	    memcpy(HC, hash, length_of_HC);

            // 将HC和hash转换为十六进制字符串以便打印
            char hex_HC[length_of_HC * 2 + 1];
            char hex_hash[SHA256_DIGEST_SIZE * 2 + 1];
            to_hex_string(HC, length_of_HC, hex_HC);
            to_hex_string(hash, SHA256_DIGEST_SIZE, hex_hash);

            // printk(KERN_INFO "HC: %s", hex_HC);
            // printk(KERN_INFO "hash: %s", hex_hash);
            //options_header
            new_iph->options[0] = 0x44;
            new_iph->options[1] = 0x24;
            new_iph->options[2] = 0x05;
            new_iph->options[3] = 0x03;
            
            //匿名身份标识
            new_iph->options[4] = 0x38; 
            new_iph->options[5] = 0x65;
            new_iph->options[6] = 0xee;
            new_iph->options[7] = 0xd5;
            new_iph->options[8] = 0x4d;
            new_iph->options[9] = 0x9a;
            new_iph->options[10] = 0x01;
            
            int j;
            for(j = 0; j < 24; j++)
            {
            	new_iph->options[j + 11] = hash[j];
            }
            
            //whether or not create sign pkt
            mark_flag = (mark_flag + 1 ) % sign_interval;
            if (mark_flag == 1){
            	new_iph->options[35] = 0x01;
            }
            
            skb->network_header = skb->data - skb->head;
            
            new_iph->check = calculate_ip_checksum(new_iph);
            if(skb->data_len != 0){
                skb_linearize(skb);
            }
            return NF_ACCEPT; // accept tcP packet
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;

static int __init nf_minifirewall_init(void)
{
    nf_blockicmppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    old_iph = (struct iphdr *)kmalloc(sizeof(struct iphdr), GFP_KERNEL);
    if (nf_blockicmppkt_ops != NULL)
    {
        nf_blockicmppkt_ops->hook = (nf_hookfn *)nf_blockicmppkt_handler;
        nf_blockicmppkt_ops->hooknum = 	NF_INET_LOCAL_OUT;
        nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
        nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST; // set the priority

        nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
    }
    strcpy(HC, "");
    return 0;
}

static void __exit nf_minifirewall_exit(void)
{
    kfree(old_iph);
    if (nf_blockicmppkt_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
        kfree(nf_blockicmppkt_ops);
    }
    printk(KERN_INFO "Exit");
}

module_init(nf_minifirewall_init);
module_exit(nf_minifirewall_exit);
