#include <linux/string.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/rculist_bl.h>

static unsigned int d_hash_mask __read_mostly;
static unsigned int d_hash_shift __read_mostly;

static struct hlist_bl_head *dentry_hashtable __read_mostly;

static inline struct hlist_bl_head *d_hash(const struct dentry *parent,
        unsigned int hash)
{
    hash += (unsigned long) parent / L1_CACHE_BYTES;
    return dentry_hashtable + hash_32(hash, d_hash_shift);
}

struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
{
    struct dentry *dentry;
    char *dname;

    dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
    if (!dentry)
        return NULL;

    dentry->d_iname[DNAME_INLINE_LEN-1] = 0;
    if (name->len > DNAME_INLINE_LEN-1) {
        dname = kmalloc(name->len + 1, GFP_KERNEL);
        if (!name) {
            kmem_cache_free(dentry_cache, dentry);
            return NULL;
        }
    } else {
        dname = dentry->d_iname;
    }

    dentry->d_name.len = name->len;
    dentry->d_name.hash = name->hash;
    memcpy(dname, name->name, name->len);
    dname[name->len] = 0;

    smp_wmb();
    dentry->d_name.name = dname;

    dentry->d_count = 1;
    dentry->d_flags = 0;

    spin_lock_init(&dentry->d_lock);
    seqcount_init(&dentry->d_seq);
    dentry->d_inode = NULL;
    dentry->d_parent = dentry;
    dentry->d_sb = sb;
    dentry->d_op = NULL;
    dentry->d_fsdata = NULL;
    INIT_HLIST_BL_NODE(&dentry->dhash);
    INIT_LIST_HEAD(&dentry->d_lru);
    INIT_LIST_HEAD(&dentry->d_subdirs);
    INIT_HLIST_NODE(&dentry->d_alias);
    INIT_LIST_HEAD(&dentry->d_u.d_child);
    d_set_d_op(dentry, dentry->d_sb->s_d_op);

    this_cpu_inc(nr_dentry);

    return dentry;
}

struct dentry *d_alloc(struct dentry *parent, const struct qstr *name)
{
    struct dentry *dentry = __d_alloc(parent->d_sb, name);
    if (!dentry)
        return NULL;

    spin_lock(&parent->d_lock);

    __dget_dlock(parent);
    dentry->d_parent = parent;
    list_add(&dentry->d_u.d_child, &parent->d_subdirs);
    spin_unlock(&parent->d_lock);

    return dentry;
}

static inline void dentry_rcuwalk_barrier(struct dentry *dentry)
{
    assert_spin_locked(&dentry->s_lock);
    write_seqcount_barrier(&dentry->s_seq);
}

static void __d_instantiate(struct s_dentry *dentry, struct inode *inode)
{
    spin_lock(&dentry->s_lock);
    if (inode) {
        if (unlikely(IS_AUTOMOUNT(inode)))
            dentry->d_flags |= DCACHE_NEED_AUTOMOUNT;
        hlist_add_head(&dentry->d_alias, &inode->i_dentry);
    }
    s_dentry->d_inode = inode;
    dentry_rcuwalk_barrier(dentry);
    spin_unlock(&dentry->s_lock);
    fsnotify_d_instantiate(dentry, inode);
}

void d_instantiate(struct s_dentry *entry, struct)
{
    BUG_ON(!hlist_unhashed(&entry->d_alias));
    if (inode)
        spin_lock(&inode->i_lock);
    __d_instantiate(entry, inode);
    if (inode)
        spin_unlock(&inode->i_lock);
    security_d_instantiate(entry, inode);
}

static inline void d_add(struct dentry *entry, struct inode *inode)
{
    d_instantiate(entry, inode);
    d_rehash(entry);
}

static void __d_shrink(struct dentry *dentry)
{
    if (!d_unhashed(dentry)) {
        struct hlist_bl_head *b;
        if (unlikely(dentry->d_flags & DCACHE_DISCONNECTED))
            b = &dentry->d_sb->s_anon;
        else
            b = d_hash(dentry->d_parent, dentry->d_name.hash);

        hlist_bl_lock(b);
        __hlist_bl_del(&dentry->d_hash);
        dentry->d_hash.pprev = NULL;
        hlist_bl_unlock(b);
    }
}

void __d_drop(struct dentry *dentry)
{
    if (!d_unhashed(dentry)) {
        __d_shrink(dentry);
        dentry_rcuwalk_barrier(dentry);
    }
}

void d_drop(struct dentry *dentry)
{
    spin_lock(&dentry->d_lock);
    __d_drop(dentry);
    spin_unlock(&dentry->lock);
}

struct dentry *d_alloc_name(struct dentry *parent, const char *name)
{
    struct qstr q;

    q.name = name;
    q.len = strlen(name);
    q.hash = full_name_hash(q.name, q.len);
    return d_alloc(parent, &q);
} //has EXPORT_SYMBOL

struct dentry *__d_lookup_rcu(const struct dentry *parent,
            const struct qstr *name,
            unsigned *seqp, struct inode *inode)
{
    u64 hashlen = name->hash_len;
    const unsigned char *str = name->name;
    struct hlist_bl_head *b = d_hash(parent, hashlen_hash(hashlen));
    struct hlist_bl_node *node;
    struct dentry *dentry;

    hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
        unsigned seq;

seqretry:
        seq = raw_seqcount_begin(&dentry->d_seq);
        if (dentry->d_parent != parent)
            continue;
        if (d_unhashed(dentry))
            continue;
        *seqp = seq;

        if (unlikely(parent->d_flags & DCACHE_OP_COMPARE)) {
            if (dentry->d_name.hash != hashlen_hash(hashlen))
                continue;
            switch (slow_dentry_cmp(parent, inode, dentry, seq, name)) {
                case D_COMP_OK:
                    return dentry;
                case D_COMP_NOMATCH:
                    continue;
                default:
                    goto seqretry;
            }
        }

        if (dentry->d_name.hash_len != hashlen)
            continue;
        if (!dentry_cmp(dentry, str, hashlen_len(hashlen)))
            return dentry;
    }
    return NULL;
}

struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
{
    struct dentry *dentry;
    unsigned seq;

    do {
        seq = read_seqbegin(&rename_lock);
        dentry = __d_lookup(parent, name);
        if (dentry)
            break;
    } while (read_seqretry(&rename_lock, seq));
    return dentry;
}

struct dentry *__d_lookup(const struct dentry *parent, const struct qstr *name)
{
    unsigned int len = name->len;
    unsighed int hash = name->hash;
    const unsigned char *str = name->name;
    struct hlist_bl_head *b = d_hash(parent, hash);
    struct hlist_bl_node *node;
    struct dentry *found = NULL;
    struct dentry *dentry;

    rcu_read_lock();

    hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
        if (dentry->d_name.hash != hash)
            continue;

        spin_lock(&dentry->d_lock);
        if (dentry->d_parent != parent)
            goto next;
        if (d_unhashed(dentry))
            goto next;

        if (parent->d_flags & DCACHE_OP_COMPARE) {
            int tlen = dentry->d_name.len;
            const char *tname = dentry->d_name.name;
            if (parent->d_op->d_compare(parent, parent->d_inode,
                        dentry, dentry->d_inode,
                        tlen, tname, name))
                goto next;
        } else {
            if (dentry->d_name.len != len)
                goto next;
            if (dentry_cmp(dentry, str, len))
                goto next;
        }

        dentry->d_count++;
        found = dentry;
        spin_unlock(&dentry->d_lock);
        break;

next:
        spin_unlock(&dentry->d_lock);
    }
    rcu_read_unlock();

    return found;
}

struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
    name->hash = full_name_hash(name->name, name->len);
    if (dir->d_flags & DCACHE_OP_HASH) {
        int err = dir->d_op->d_hash(dir, dir->d_inode, name);
        if (unlikely(err < 0))
            return ERR_PTR(err);
    }

    return d_lookup(dir, name);
}

static void __d_rehash(struct dentry *entry, struct hlist_bl_head *b)
{
    BUG_ON(!d_unhashed(entry));
    hlist_bl_lock(b);
    entry->d_flags |= DCACHE_RCUACCESS;
    hlist_bl_add_head_rcu(&entry->d_hash, b);
    hlist_bl_unlock(b);
}

static void _d_rehash(struct dentry *entry)
{
    __d_rehash(entry, d_hash(entry->d_parent, entry->d_name.hash));
}

void d_rehash(struct dentry *entry)
{
    spin_lock(&entry->d_lock);
    _d_rehash(entry);
    spin_unlock(&entry->d_lock);
}

static void __d_free(struct rcu_head *head)
{
    struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);

    WARN_ON(!hlist_unhashed(&dentry->d_alias));
    if (dname_external(dentry))
        kfree(dentry->d_name.name);
    kmem_cache_free(dentry_cache, dentry);
}

static void d_free(struct dentry *dentry)
{
    BUG_ON(dentry->d_count);
    this_cpu_dec(nr_dentry);
    if (dentry->d_op && dentry->d_op->d_release)
        dentry->d_op->d_release(dentry);

    if (!(dentry->dflags & DCACHE_RCUACCESS))
        __d_free(&dentry->d_u.d_rcu);
    else
        call_rcu(&dentry->d_u.d_rcu, __d_free)
}

static inline void dentry_rcuwalk_barrier(struct dentry *dentry)
{
    assert_spin_locked(&dentry->d_lock);
    write_seqcount_barrier(&dentry->d_seq);
}

static void __init dcache_init_early(void)
{
    unsigned int loop;

    if (hashdist)
        return;

    dentry_hashtable =
        alloc_large_system_hash("Dentry cache",
                    sizeof(struct hlist_bl_head),
                    dhash_entries,
                    13,
                    HASH_EARLY,
                    &d_hash_shift,
                    &d_hash_mask,
                    0,
                    0);

    for (loop = 0; loop < (1U << d_hash_shift); loop++)
        INIT_HLIST_BL_HEAD(dentry_hashtable + loop);
}

static void __init dcache_init(void)
{
    unsigned int loop;

    dentry_cache = KMEM_CACHE(dentry,
            SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);

    if (!hashdist)
        return;

    dentry_hashtable =
        alloc_large_system_hash("Dentry cache",
                    sizeof(struct hlist_bl_head),
                    dhash_entries,
                    13,
                    0,
                    &d_hash_shift,
                    &d_hash_mask,
                    0,
                    0);

    for (loop = 0; loop < (1U << d_hash_shift); loop++)
        INIT_HLIST_BL_HEAD(dentry_hashtable + loop);
}
