
#define CMD_NEW_CHANNEL 0x77617364
#define CMD_DELETE_CHANNEL 0x77617365
#define CMD_INC_BUF_SIZE 0x77617366
#define CMD_DEC_BUF_SIZE 0x77617366
#define CMD_READ_BUF 0x77617368
#define CMD_WRITE_BUF 0x77617369
#define CMD_CHANGE_POS 0x7761736a
#define CMD_DESTROY_CHANNEL 0x7761736b

#define HIGH_KERNEL_ADDRESS_BORDER ((uint64_t)0xffffffff80000000)

typedef struct context_t
{
    channel_t *act_channel;
    struct mutex *lock;
} context_t;

typedef struct channel_t
{
    int ref_count;
    unsigned int index;
    char *buf;
    size_t buf_size;
    long pos;
} channel_t;

typedef struct create_channel_arg_t
{
    size_t buf_size;
    int index;
} create_channel_arg_t;

typedef struct delete_channel_arg_t
{
    int index;
} delete_channel_arg_t;

typedef struct realloc_channel_arg_t
{
    int index;
    long count;
} realloc_channel_arg_t;

typedef struct read_buf_arg_t
{
    char unused_field[8];
    void *dst;
    size_t count;
} read_buf_arg_t;

typedef struct write_buf_arg_t
{
    char unused_field[8];
    void *src;
    size_t count;
} write_buf_arg_t;

typedef struct change_pos_arg_t
{
    char unused_field[8];
    size_t new_pos;
    int flag;
} change_pos_arg_t;

typedef struct destroy_channel_arg_t
{
    int index;
} destroy_channel_arg_t;

int csaw_open(struct inode *inode, struct file *filep)
{
    context_t *context;
    context = kmalloc(sizeof(context_t), GFP_KERNEL);

    mutex_init(&context->lock, &state->lock, ipc_idr);

    filep->private_data = context;
    return 0;
}

int csaw_release(struct inode *inode, struct file *filep)
{
    context_t *context;
    channel_t *channel;

    context = (context_t*) filep->private_data;
    
    channel = context->act_channel;
    if (channel) {
        channel->ref_count -= 1;
        if (channel->ref_count == 0)
            ipc_channel_destroy(channel);
    }

    kfree(context);
    return 0;
}

channel_t *get_channel_by_id(int index)
{
    channel_t channel;

    channel = radix_tree_lookup(ipc_idr, (long)index);

    if (channel)
    {
        channel->ref_count += 1;
    }

    return channel;
}

unsigned long allocate_new_ipc_channel(size_t buf_size, channel_t **new_channel_placeholder)
{
    channel_t *new_channel;
    char *buf;
    unsigned long index;

    if (!buf_size) 
        return -EINVAL;

    new_channel = kmalloc(sizeof(channel_t), GFP_KERNEL);
    buf = kmalloc(buf_size, GFP_KERNEL);

    new_channel->ref_count = 1;
    new_channel->buf = buf;
    new_channel->buf_size = buf_size;

    idr_alloc_cmd(&ipc_idr, new_channel, &index, 1, 0, GFP_KERNEL);
    new_channel->index = index;

    *new_channel_placeholder = new_channel;
    return 0;
}

long create_new_ipc_channel(context_t *context, create_channel_arg_t *arg)
{
    create_channel_arg_t kernel_arg;
    channel_t *new_channel;

    copy_from_user(&kernel_arg, arg, sizeof(create_channel_arg_t));

    if (context->act_channel) 
        return -EBUSY;

    allocate_new_ipc_channel(kernel_arg.buf_size, &new_channel);
    kernel_arg.index = new_channel->index;
    context->act_channel = new_channel;

    copy_to_user(arg, &kernel_arg, sizeof(create_channel_arg_t));
}

void ipc_channel_destroy(channel_t *channel)
{
    radix_tree_delete(ipc_idr, channel->index);
    kfree(channel->buf);
    kfree(channel);
}

long del_channel(context_t *context, delete_channel_arg_t *arg)
{
    delete_channel_arg_t kernel_arg;
    channel_t channel;
    int index;

    copy_from_user(&kernel_arg, arg, sizeof(delete_channel_arg_t));

    channel = get_channel_by_id(kernel_arg.index);

    channel->ref_count -= 1;
    if (channel->ref_count == 0)
    {
        ipc_channel_destroy(channel);
    }
}

int realloc_ipc_channel(int index, long count, int sign)
{
    channel_t *channel;
    size_t new_buf_size;
    char *new_buf;

    channel = get_channel_by_id(index);

    if (!sign)
        new_buf_size = channel->buf_size - count;
    else
        new_buf_size = channel->buf_size + count;

    new_buf = krealloc(channel->buf, new_buf_size, GFP_KERNEL);
    channel->buf = new_buf;

    channel->ref_count -= 1;
    if (channel->ref_count == 0)
        ipc_channel_destroy(channel);

    return 0;
}

long inc_buf_size(context_t *context, realloc_channel_arg_t *arg)
{
    realloc_channel_arg_t kernel_arg;

    copy_from_user(&kernel_arg, arg, 0x10);

    realloc_ipc_channel(kernel_arg.index, kernel_arg.count, 1);

    return 0;
}

long dec_buf_size(context_t *context, realloc_channel_arg_t *arg)
{
    realloc_channel_arg_t kernel_arg;

    copy_from_user(&kernel_arg, arg, 0x10);

    realloc_ipc_channel(kernel_arg.index, kernel_arg.count, 0);

    return 0;
}

long read_buf(context_t *context, read_buf_arg_t *arg)
{
    read_buf_arg_t kernel_arg;
    channel_t *channel;

    copy_from_user(&kernel_arg, arg, 0x18);

    channel = context->act_channel;
    if (!channel)
        return -1;

    if (channel->pos + kernel_arg.count <= channel->buf_size)
    {
        copy_to_user(kernel_arg.dst, &channel->buf[channel->pos], kernel_arg.count);
    }

    return 0;
}

long write_buf(context_t *context, write_buf_arg_t *arg)
{
    write_buf_arg_t kernel_arg;
    channel_t *channel;

    copy_from_user(&kernel_arg, arg, 0x18);

    channel = context->act_channel;
    if (!channel)
        return -1;

    if (

    if (channel->pos + kernel_arg.count <= channel->buf_size) && (channel->buf + channel->pos) >= HIGH_KERNEL_ADDRESS_BORDER)
    {
        strncpy_from_user(&channel->buf[channel->pos], kernel_arg.src, kernel_arg.count);
        return 0;
    }

    return -1;
}

long change_pos(context_t *context, change_pos_arg_t *arg)
{
    change_pos_arg_t kernel_arg;
    channel_t *channel;

    copy_from_user(&kernel_arg, arg, sizeof(change_pos_arg_t));
    channel = context->act_channel;

    if (!channel)
        return -1;

    if (!kernel_arg.flag && kernel_arg.new_pos < channel->buf_size)
    {
        channel->pos = kernel_arg.new_pos;
        return 0;
    }

    return -1;
}

long close_ipc_channel(context_t *context, int index) {
    channel_t *channel;

    channel = get_channel_by_id(index);
    if (channel >= HIGH_KERNEL_ADDRESS_BORDER)
        return channel;

    if (channel == context->act_channel) {
        context->act_channel = 0;
        channel->ref_count -= 1;
        if (channel->ref_count == 0) 
            ipc_channel_destroy(channel);
    }

    channel->ref_count -= 1;
    if (channel->ref_count == 0)
        ipc_channel_destroy(channel);
    
    return 0;
}

long destroy_channel(context_t *context, destroy_channel_arg_t *arg) {
    destroy_channel_arg_t kernel_arg;
    
    copy_from_user(&kernel_arg, arg, 0x4);

    return close_ipc_channel(context, kernel_arg.index);
}

long csaw_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    context_t *context;

    context = (context_t *)filep->private_data;

    switch (cmd)
    {
    case CMD_NEW_CHANNEL:
        return create_new_ipc_channel(context, (create_channel_arg_t *)arg);

    case CMD_DELETE_CHANNEL:
        return del_channel(context, (delete_channel_arg_t *)arg);

    case CMD_INC_BUF_SIZE:
        return inc_buf_size(context, (realloc_channel_arg_t *)arg);

    case CMD_DEC_BUF_SIZE:
        return dec_buf_size(context, (realloc_channel_arg_t *)arg);

    case CMD_READ_BUF:
        return read_buf(context, (read_buf_arg_t *)arg);

    case CMD_WRITE_BUF:
        return write_buf(context, (write_buf_arg_t *)arg);

    case CMD_CHANGE_POS:
        return change_pos(context, (change_pos_arg_t *)arg);

    case CMD_DESTROY_CHANNEL:
        return destroy_channel(context, (destroy_channel_arg_t *) arg);

    default:
        break;
    }
}