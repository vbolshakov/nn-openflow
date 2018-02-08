 /* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */
#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mm.h>  
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ftrace.h>

#include "openflow13.h"
#include "openflow.h"

// length of the two memory areas
#define FTPAGES      256
#define PBPAGES      4 
#ifndef VM_RESERVED
# define  VM_RESERVED   (VM_DONTEXPAND | VM_DONTDUMP)
#endif

//  Local variables
struct flow_table *flow_table;
struct pbuffer *pk_buffer;
struct dentry  *fileret, *dirret;
struct mmap_info *op_info;
static struct timer_list of_timer;

// original pointer for kmalloc'd area as returned by kmalloc
static void *flow_table_ptr;
static void *pk_buffer_ptr;

// Function declarations
void mmap_open(struct vm_area_struct *vma);
void mmap_close(struct vm_area_struct *vma);
static int mmap_mmap(struct file *filp, struct vm_area_struct *vma);
int mmap_kmem(struct file *filp, struct vm_area_struct *vma);
void of_timer_callback(unsigned long data);

// helper function, mmap's the kmalloc'd area which is physically contiguous
int mmap_kmem_flow_table(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    long length = vma->vm_end - vma->vm_start;

    /* check length - do not allow larger mappings than the number of pages allocated */
    if (length > FTPAGES * PAGE_SIZE) return -EIO;

    /* map the whole physically contiguous area in one piece */
    if ((ret = remap_pfn_range(vma, vma->vm_start, virt_to_phys((void *)flow_table) >> PAGE_SHIFT, length, vma->vm_page_prot)) < 0)
    {
        return ret;
    }
    
    //printk(KERN_INFO "nn_OpenFlow: flow table - vma->vm_start = %x , vma->vm_end = %x , length = %d\n",vma->vm_start, vma->vm_end, length);
    return 0;
}

int mmap_kmem_pk_buffer(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    long length = vma->vm_end - vma->vm_start;

    /* check length - do not allow larger mappings than the number of pages allocated */
    if (length > PBPAGES * PAGE_SIZE) return -EIO;

    /* set to not cache */
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    //vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
    
    /* map the whole physically contiguous area in one piece */
    if ((ret = remap_pfn_range(vma, vma->vm_start, virt_to_phys((void *)pk_buffer) >> PAGE_SHIFT, length, vma->vm_page_prot)) < 0)
    {
        return ret;
    }
    
    //printk(KERN_INFO "nn_OpenFlow: pk buffer - vma->vm_start = %x , vma->vm_end = %x , length = %d\n",vma->vm_start, vma->vm_end, length);
    return 0;
}

int mmapfop_close(struct inode *inode, struct file *filp)
{
	//printk(KERN_INFO "mmap file closed\n");
    return 0;
}
 
int mmapfop_open(struct inode *inode, struct file *filp)
{
    //printk(KERN_INFO "mmap file opened.\n");
    return 0;
}
 
static const struct file_operations mmap_fops = {
    .open = mmapfop_open,
    .release = mmapfop_close,
    .mmap = mmap_mmap,
    .owner = THIS_MODULE,
};

/* character device mmap method */
static int mmap_mmap(struct file *filp, struct vm_area_struct *vma)
{
    //printk(KERN_INFO "nn_OpenFlow: Called mmap - offset = %d.\n", vma->vm_pgoff);
    /* at offset 0 we map the kmalloc'd area */
    if (vma->vm_pgoff == 0)
    {
        return mmap_kmem_flow_table(filp, vma);
    }
    /* at offset FTPAGES we map the kmalloc'd area */
    if (vma->vm_pgoff == FTPAGES) {
        return mmap_kmem_pk_buffer(filp, vma);
    }

    /* at any other offset we return an error */
    return -EIO;
}

static int __init nn_openflow_init(void)
{
    //printk(KERN_INFO "nn_OpenFlow: Module loaded.\n");

    /* allocate a memory area with kmalloc. Will be rounded up to a page boundary */
    if ((flow_table_ptr = kmalloc((FTPAGES + 2) * PAGE_SIZE, GFP_KERNEL)) == NULL) 
    {
        return -ENOMEM;
    }
    /* round it up to the page bondary */
    flow_table = (int *)((((unsigned long)flow_table_ptr) + PAGE_SIZE - 1) & PAGE_MASK);
    printk(KERN_INFO "nn_OpenFlow: flow_table allocated at %p\n", (void*)flow_table);


    /* allocate a memory area with kmalloc. Will be rounded up to a page boundary */
    if ((pk_buffer_ptr = kmalloc((PBPAGES + 2) * PAGE_SIZE, GFP_KERNEL)) == NULL) 
    {
        return -ENOMEM;
    }
    /* round it up to the page bondary */
    pk_buffer = (int *)((((unsigned long)pk_buffer_ptr) + PAGE_SIZE - 1) & PAGE_MASK);
    //printk(KERN_INFO "nn_OpenFlow: pk_buffer allocated at %p\n", (void*)pk_buffer);


    /* mark the pages reserved */
    for (int i = 0; i < FTPAGES * PAGE_SIZE; i+= PAGE_SIZE)
    {
        SetPageReserved(virt_to_page(((unsigned long)flow_table) + i));
    }

    /* mark the pages reserved */
    for (int i = 0; i < PBPAGES * PAGE_SIZE; i+= PAGE_SIZE)
    {
        SetPageReserved(virt_to_page(((unsigned long)pk_buffer) + i));
    }
    
    memset(flow_table, 0, FTPAGES * PAGE_SIZE);
    memset(pk_buffer, 0, PBPAGES * PAGE_SIZE);

    dirret = debugfs_create_dir("openflow", NULL);
    fileret = debugfs_create_file("data", 0644, dirret, NULL, &mmap_fops);

    // Create a timer to use for packet outs, etc.
    //setup_timer(&of_timer, of_timer_callback, 0 );
    //printk(KERN_INFO "nn_OpenFlow: Starting OF timer (%ld)\n", jiffies );
    //int ret = mod_timer(&of_timer, jiffies + msecs_to_jiffies(1000));
    //if (ret) printk(KERN_INFO "nn_OpenFlow: unable set OF timer\n");

    return 0;    // Non-zero return means that the module couldn't be loaded.
}

void of_timer_callback(unsigned long data)
{
  //nnOF_timer();
  //int ret = mod_timer(&of_timer, jiffies + msecs_to_jiffies(1000));     //reset timer
  //if (ret) printk(KERN_INFO "nn_OpenFlow: unable reset timer\n");
}

static void __exit nn_openflow_exit(void)
{
    printk(KERN_INFO "nn_OpenFlow: Module removed.\n");
    debugfs_remove_recursive(dirret);
    int ret = del_timer(&of_timer);
    if (ret) printk(KERN_INFO "nn_OpenFlow: Unable to delete timer\n");
}

/*
 *	Main OpenFlow table lookup Function
 *
 *	@param p_uc_data - pointer to the packet buffer.
 *	@param ul_size - Size of the packet.
 *	@param port	- In Port.
 *
 */
void nnOpenflow(u32 in_port, struct sk_buff *skb, struct net_device *dev, struct output_list *output_list)
{
    u16 ethtype = 0;
    u8 *dst_ehdr;

    trace_printk("nn_OpenFlow: Received packet from port %d - dev = 0x%p, skb = 0x%p\n", in_port, (void*)dev, (void*)skb);
    // If OpenFlow is disabled we process packets normally
    if (flow_table->enabled == 0) 
    {
        output_list->outport[0] = OFPP13_NORMAL;
        output_list->skb[0] = skb; 
        output_list->dev[0] = dev;
        output_list->outport[1] = PORT_DROP;
        output_list->skb[1] = NULL; 
        output_list->dev[1] = NULL;
        return;
    }
    // If Auth Bypass is enabled we just process EAPOL packets (0x888E) normally 
    if (flow_table->auth_bypass == 1)
    {
        dst_ehdr = skb->data;
        dst_ehdr = dst_ehdr+12;
        memcpy(&ethtype, dst_ehdr, 2);
        if (ethtype == 0x888E)
        {
            output_list->outport[0] = OFPP13_NORMAL;
            output_list->skb[0] = skb; 
            output_list->dev[0] = dev;
            output_list->outport[1] = PORT_DROP;
            output_list->skb[1] = NULL; 
            output_list->dev[1] = NULL;
            return;
        }
        
    }
    // Update port stats / status
    flow_table->port_status[in_port-1] = true;
    flow_table->phys13_port_stats[in_port-1].rx_packets += 1;
    flow_table->phys13_port_stats[in_port-1].rx_bytes += skb->len;
    nnOF13_tablelookup(skb, dev, in_port, output_list);
    if (output_list->outport[0] != PORT_DROP)
    {
        flow_table->phys13_port_stats[output_list->outport[0]-1].tx_packets += 1;
        flow_table->phys13_port_stats[output_list->outport[0]-1].tx_bytes += output_list->skb[0]->len;
    }
    return;
}

/*
 *  Packet poll request
 *
 *  @param skb - pointer to the packet buffer.
 *  @param dev - pointer to the device.
 *
 */
struct packet_out nnPacketout(int buffer_id)
{
    struct packet_out pkt_out;

    pkt_out.inport = 0;
    pkt_out.outport = -1;
    pkt_out.dev = NULL;
    pkt_out.skb = NULL;

    if(pk_buffer->buffer[buffer_id].type == PB_PENDING || pk_buffer->buffer[buffer_id].type == PB_PACKETIN) pk_buffer->buffer[buffer_id].age++;
    
    // Buffer entry has timed out so remove entry
    if (pk_buffer->buffer[buffer_id].age > 4)
    {
        pk_buffer->buffer[buffer_id].age = 0;
        pk_buffer->buffer[buffer_id].type = PB_EMPTY;
        trace_printk("nn_OpenFlow: Packet Buffer %d timed out!\n", buffer_id);
        kfree_skb(pk_buffer->buffer[buffer_id].skb);
        return pkt_out;
    }

    // Buffer entry is a PACKET OUT so return details
    if(pk_buffer->buffer[buffer_id].type == PB_PACKETOUT)
    {
        pkt_out.skb = pk_buffer->buffer[buffer_id].skb;
        pkt_out.dev = pk_buffer->buffer[buffer_id].dev;
        pkt_out.inport = pk_buffer->buffer[buffer_id].inport;
        pkt_out.outport = pk_buffer->buffer[buffer_id].outport;
        trace_printk("nn_OpenFlow: Packet out found in buffer %d - dev = 0x%p, skb = 0x%p, outport = 0x%x, inport = %d\n", buffer_id, (void*)pkt_out.dev, (void*)pkt_out.skb, pkt_out.outport, pkt_out.inport);
        pk_buffer->buffer[buffer_id].type = PB_EMPTY;     
        return pkt_out;
    }
    return pkt_out;
}

/*
 *  Port status update
 *
 *  @param port - pointer to the packet buffer.
 *  @param state - pointer to the packet buffer.
 *
 */
void nnPortstatus(int port, int state)
{
    if (state == true)
    {
        flow_table->port_status[port-1] = true;
        trace_printk("Port %d is UP\n", port);
    } else {
        flow_table->port_status[port-1] = false;
        trace_printk("Port %d is DOWN\n", port);
    }
}


EXPORT_SYMBOL(nnOpenflow);
EXPORT_SYMBOL(nnPacketout);
EXPORT_SYMBOL(nnPortstatus);

module_init(nn_openflow_init);
module_exit(nn_openflow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Northbound Networks");
MODULE_DESCRIPTION("Mac80211 Openflow Interface");