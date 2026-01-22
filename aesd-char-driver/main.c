/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
#include <linux/uaccess.h>
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("MESHAL ALHAZMI");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");

    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    // if (filp->private_data != &aesd_device) PDEBUG("unexpected dev");

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset = 0;
    size_t to_copy;
    int res;

    res = mutex_lock_interruptible(&dev->lock);
    if (res)
    {
        retval = -ERESTARTSYS;
        return retval;
    }
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);
    if (!entry)
    {
        retval = 0; // EOF
        goto out;
    }
    to_copy = min(count, entry->size - entry_offset);
    if (copy_to_user(buf, entry->buffptr + entry_offset, to_copy))
    {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += to_copy;
    retval = to_copy;
out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *kbuf = NULL;
    char *nl = NULL;
    size_t total = dev->pending.size + count;
    ssize_t retval = count;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    kbuf = kmalloc(total, GFP_KERNEL);
    if (!kbuf)
    {
        retval = -ENOMEM;
        goto out;
    }

    if (dev->pending.size)
        memcpy(kbuf, dev->pending.buffptr, dev->pending.size);

    if (copy_from_user(kbuf + dev->pending.size, buf, count))
    {
        retval = -EFAULT;
        goto out_free;
    }

    nl = memchr(kbuf, '\n', total);
    if (!nl)
    {
        kfree(dev->pending.buffptr);
        dev->pending.buffptr = kbuf;
        dev->pending.size = total;
        goto out;
    }

    /* free overwritten entry if buffer full */
    if (dev->buffer.full)
    {
        struct aesd_buffer_entry *old = &dev->buffer.entry[dev->buffer.in_offs];
        kfree(old->buffptr);
    }

    /* add complete command */
    {
        struct aesd_buffer_entry entry = {
            .buffptr = kbuf,
            .size = (nl + 1) - kbuf};
        aesd_circular_buffer_add_entry(&dev->buffer, &entry);
    }

    /* store trailing bytes as new pending */
    if ((nl + 1) < (kbuf + total))
    {
        size_t rem = (kbuf + total) - (nl + 1);
        dev->pending.buffptr = kmalloc(rem, GFP_KERNEL);
        if (dev->pending.buffptr)
        {
            memcpy(dev->pending.buffptr, nl + 1, rem);
            dev->pending.size = rem;
        }
        else
        {
            dev->pending.size = 0;
        }
    }
    else
    {
        dev->pending.buffptr = NULL;
        dev->pending.size = 0;
    }

out:
    mutex_unlock(&dev->lock);
    return retval;

out_free:
    kfree(kbuf);
    goto out;
}
struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev\n", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);
    aesd_device.pending.buffptr = NULL;
    aesd_device.pending.size = 0;

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    printk(KERN_INFO "Model setup completed\n");
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    struct aesd_buffer_entry *entry;
    uint8_t index;
    mutex_lock(&aesd_device.lock);

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index)
    {
        kfree(entry->buffptr);
        entry->buffptr = NULL;
    }
    if (aesd_device.pending.buffptr)
    {
        kfree(aesd_device.pending.buffptr);
        aesd_device.pending.buffptr = NULL;
        aesd_device.pending.size = 0;
    }

    mutex_unlock(&aesd_device.lock);
    cdev_del(&aesd_device.cdev);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
