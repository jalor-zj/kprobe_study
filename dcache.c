#include <linux/string.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/rculist_bl.h>

static unsigned int s_hash_mask __read_mostly;
static unsigned int s_hash_shift __read_mostly;

static struct hlist_bl_head *dentry_hashtable __read_mostly;

static inline struct hlist_bl_head *d_hash(const struct s_dentry *parent,
        unsigned int hash)
{
    hash += (unsigned long) parent / L1_CACHE_BYTES;
    return dentry_hashtable + hash_32(hash, s_hash_shift);
}

static inline int d_unhashed(struct s_dentry *dentry)
{
    return hlist_bl_unhashed(&dentry->s_hash);
}

struct s_dentry *__s_alloc(const struct s_qstr *name)
{
    struct s_dentry *dentry;
    char *dname;

    dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
    if (!dentry)
        return NULL;

    dname = kmalloc(name->len + 1, GFP_KERNEL);
    if (!name) {
        kmem_cache_free(dentry_cache, dentry);
        return NULL;
    }

    dentry->s_name.len = name->len;
    dentry->s_name.hash = name->hash;
    memcpy(dname, name->name, name->len);
    dname[name->len] = 0;

    smp_wmb();
    dentry->s_name.name = dname;

    dentry->s_count = 1;
    dentry->s_action = 0;

    spin_lock_init(&dentry->s_lock);
    seqcount_init(&dentry->s_seq);
    dentry->s_parent = dentry;
    dentry->d_sb = sb;
    INIT_HLIST_BL_NODE(&dentry->s_hash);
    INIT_LIST_HEAD(&dentry->s_lru);
    INIT_LIST_HEAD(&dentry->s_subdirs);
    INIT_LIST_HEAD(&dentry->s_u.s_child);

    return dentry;
}

/*this must be called with s_lock is hold*/
static inline void __sget_slock(struct s_dentry *dentry)
{
    dentry->s_count++;
}

static inline void __sget(struct s_dentry *dentry)
{
    spin_lock(&dentry->s_lock);
    __sget_slock(dentry);
    spin_unlock(&dentry->s_lock);
}

struct s_dentry *s_alloc(struct s_dentry *parent, const struct s_qstr *name)
{
    struct s_dentry *dentry = __s_alloc(name);
    if (!dentry)
        return NULL;

    spin_lock(&parent->s_lock);

    __sget_slock(parent);
    dentry->s_parent = parent;
    list_add(&dentry->s_u.s_child, &parent->s_subdirs);
    spin_unlock(&parent->s_lock);

    return dentry;
}

static struct s_dentry *lookup_dcache(struct s_qstr *name, struct s_dentry *dir,
                bool *need_lookup)
{
    struct s_dentry *dentry;
    int error;

    *need_lookup = false;
    dentry = s_lookup(dir, name);
    if (!dentry) {
        dentry = d_alloc(dir, name);
        if (unlikely(!dentry))
            return ERR_PTR(-ENOMEM);

        *need_lookup = true;
    }
    return dentry;
}

static inline void dentry_rcuwalk_barrier(struct s_dentry *dentry)
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

static void __d_shrink(struct s_dentry *dentry)
{
    if (!d_unhashed(dentry)) {
        struct hlist_bl_head *b;
        b = d_hash(dentry->s_parent, dentry->s_name.hash);

        hlist_bl_lock(b);
        __hlist_bl_del(&dentry->s_hash);
        dentry->d_hash.pprev = NULL;
        hlist_bl_unlock(b);
    }
}

void __s_drop(struct s_dentry *dentry)
{
    if (!d_unhashed(dentry)) {
        __d_shrink(dentry);
        dentry_rcuwalk_barrier(dentry);
    }
}

void d_drop(struct dentry *dentry)
{
    spin_lock(&dentry->d_lock);
    __s_drop(dentry);
    spin_unlock(&dentry->lock);
}

struct s_dentry *s_alloc_name(struct s_dentry *parent, const char *name)
{
    struct s_qstr q;

    q.name = name;
    q.len = strlen(name);
    q.hash = full_name_hash(q.name, q.len);
    return s_alloc(parent, &q);
} //has EXPORT_SYMBOL

static struct s_dentry *__lookup_hash(struct s_qstr *name,
            struct s_dentry *base)
{
    bool need_lookup;
    struct s_dentry *dentry;

    dentry = lookup_dcache(name, base, &need_lookup);
    if (!need_lookup)
        return dentry;

    return looup_real(base->d_inode, dentry, flags)
}

static struct s_dentry *lookup_hash(struct nameidata *nd)
{
    return __lookup_hash(&nd->last, nd->path.dentry, nd->flags);
}

struct s_dentry *lookup_one_len(const char *name, struct s_dentry *base, int len)
{
    struct s_qstr this;
    unsigned int c;
    int err;

    this.name = name;
    this.len = len;
    this.hash = s_full_name_hash(name, len);
    if (!len)
        return ERR_PTR(-EACCES);

    if (unlikely(name[0] == '.')) {
        if (len < 2 || (len == 2 && name[1] == '.'))
            return ERR_PTR(-EACCES);
    }

    while (len--) {
        c = *(const unsigned char *)name++;
        if (c == '/' || c == '\0')
            return ERR_PTR(-EACCES);
    }

    return __lookup_hash(&this, base, 0)
}

static inline int walk_component(struct nameidata *nd, struct path *path,
            int follow)
{
    struct inode *inode;
    int err;

    if (unlikely(nd->last_type != LAST_NORM))
        return handle_dots(nd, nd->last_type);
    err = lookup_fast(nd, path, &inode);
    if (unlikely(err)) {
        if (err < 0)
            goto out_err;

        err = lookup_slow(nd, path);
        if (err < 0)
            goto out_err;

        inode = path->dentry->d_inode;
    }
    err = -ENOENT;
    if (!inode)
        goto out_path_put;

    if (should_follow_link(inode, follow)) {
        if (nd->flags & LOOKUP_RCU) {
            if (unlikely(unlazy_walk(nd, path->dentry))) {
                err = -ECHILD;
                goto out_err;
            }
        }
        BUG_ON(inode != path->dentry->d_inode);
        return 1;
    }
    path_to_nameidata(path, nd);
    nd->inode = inode;
    return 0;

out_path_put:
    path_to_nameidata(path, nd);
out_err:
    terminate_walk(nd);
    return err;
}

static int link_path_walk(const char *name, struct nameidata *nd)
{
    struct path next;
    int err;

    while (*name == '/')
        name++;
    if (!*name)
        return 0;

    for (;;) {
        struct s_qstr this;
        long len;
        int type;

        err = may_lookup(nd);
        if (err)
            break;

        len = hash_name(name, &this.hash);
        this.name = name;
        this.len = len;

        type = LAST_NORM;
        if (name[0] == '.') switch (len) {
            case 2:
                if (name[1] == '.') {
                    type = LAST_DOTDOT;
                    nd->flags |= LOOKUP_JUMPED;
                }
                break;
            case 1:
                type = LAST_DOT;
        }
        if (likely(type == LAST_NORM)) {
            struct dentry *parent = nd->path.dentry;
            nd->flags &= ~LOOKUP_JUMPED;
        }

        nd->last = this;
        nd->last_type = type;

        if (!name[len])
            return 0;

        do {
            len++;
        } while (unlikely(name[len] == '/'));
        if (!name[len])
            return 0;

        name += len;

        err = walk_component(nd, &next, LOOKUP_FOLLOW);
        if (err < 0)
            return err;

        if (err) {
            err = nested_symlink(&next, nd);
            if (err)
                return err;
        }
        if (!can_lookup(nd->inode)) {
            err = -ENOTDIR;
            break;
        }
    }
    terminate_walk(nd);
    return err;
}

static inline void lock_rcu_walk(void)
{
    rcu_read_lock();
}

static inline void unlock_rcu_walk(void)
{
    rcu_read_unlock();
}

static inline struct s_dentry *sget_slock(struct s_dentry *dentry)
{
    if (dentry)
        dentry->s_count++;
    return dentry
}

static inline struct s_dentry *sget(struct s_dentry *dentry)
{
    if (dentry) {
        spin_lock(&dentry->s_lock);
        dget_slock(dentry);
        spin_unlock(&dentry->s_lock);
    }
    return dentry;
}

static inline struct s_dentry *dentry_kill(struct s_dentry *dentry, int ref)
{
    struct s_dentry *parent;

    if (IS_ROOT(dentry))
        parent = NULL;
    else
        parent = dentry->s_parent;

    if (ref)
        dentry->s_count--;

    dentry_lru_del(dentry);
    __s_drop(dentry);
    return d_kill(dentry, parent);
}

void sput(struct s_dentry *dentry)
{
    if (!dentry)
        return;

repeat:
    if (dentry->s_count == 1)
        might_sleep();
    spin_lock(&dentry->s_lock);
    BUG_ON(!dentry->s_count);
    if (dentry->s_count > 1) {
        dentry->s_count--;
        spin_unlock(&dentry->s_lock);
        return;
    }

    if (d_unhashed(dentry))
        goto kill_it;

    dentry->s_flags |= SCACHE_REFERENCED;
    dentry_lru_add(dentry);

    dentry->s_count--;
    spin_unlock(&dentry->s_lock);
    return;

kill_it:
    dentry = dentry_kill(dentry, 1);
    if (dentry)
        goto repeat;
}

static int path_init(int dfd, const char *name, unsigned int flags,
            struct nameidata *nd, struct file **fp)
{
    int retval = 0;

    if (*name == '/') {
        if (flags & LOOKUP_RCU) {
            lock_rcu_walk();
        } else {
            sget(&nd->root);
        }
        nd->path = nd->root;
    } else if (dfd == AT_FDCWD) {
        if (flags & LOOKUP_RCU) {
            struct fs_struct *fs = current->fs;
            unsigned seq;

            lock_rcu_walk();

            do {
                seq = read_seqcount_begin(&fs->seq);
                nd->path = fs->pwd;
                nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
            } while (read_seqcount_retry(&fs->seq, seq));
        } else {
            get_fs_pwd(current->fs, &nd->path);
        }
    } else {
        struct fd f = fdget_raw(dfd);
        struct dentry *dentry;

        if (!f.file)
            return -EBADF;

        dentry = f.file->f_path.dentry;

        if (*name) {
            if (!can_lookup(dentry->d_inode)) {
                fdput(f);
                return -ENOTDIR
            }
        }

        nd->path = f.file->f_path;
        if (flags & LOOKUP_RCU) {
            if (f.need_put)
                *fp = f.file;
            nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
            lock_rcu_walk();
        } else {
            path_get(&nd->path);
            fdput(f);
        }
    }

    nd->inode = nd->path.dentry->d_inode;
    return 0;
}

static inline int lookup_last(struct nameidata *nd, struct path *path)
{
    if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
        nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

    nd->flags &= ~LOOKUP_PARENT;
    return walk_component(nd, path, nd->flags & LOOKUP_FOLLOW);
}

static int path_lookupat(int dfd, const char *name,
            unsigned int flags, struct nameidata *nd)
{
    struct file *base = NULL;
    struct path path;
    int err;

    err = path_init(dfd, name, flags | LOOKUP_PARENT, nd, &base);

    if (unlikely(err))
        return err;

    current->total_link_count = 0;
    err = link_path_walk(name, nd);

    if (!err && !(flags & LOOKUP_PARENT)) {
        err = lookup_last(nd, &path);
        while (err > 0) {
            void *cookie;
            struct path link = path;
            err = may_follow_link(&link, nd);
            if (unlikely(err))
                break;
            nd->flags |= LOOKUP_PARENT;
            err = follow_link(&link, nd, &cookie);
            if (err)
                break;
            err = lookup_last(nd, &path);
            put_link(nd, &link, cookie);
        }
    }

    if (!err)
        err = complete_walk(nd);

    if (!err && nd->flags & LOOKUP_DIRECTORY) {
        if (!can_lookup(nd->inode)) {
            path_put(&nd->path);
            err = -ENOTDIR;
        }
    }

    if (base)
        fput(base);

    if (nd->root.mnt &&  !(nd->flags & LOOKUP_ROOT)) {
        path_put(&nd->root);
        nd->root.mnt = NULL;
    }
    return err;
}

static int filename_lookup(int dfd, struct filename *name,
            unsigned int flags, struct nameidata *nd)
{
    int retval = path_lookupat(dfd, name->name, flags | LOOKUP_RCU, nd);
    if (unlikely(retval == -ECHILD))
        retval = path_lookupat(dfd, name->name, flags, nd);
    if (unlikely(retval == -ESTALE))
        retval = path_lookupat(dfd, name->name, flags | LOOKUP_REVAL, nd);

    if (likely(!retval))
        audit_inode(name, nd->path.dentry, flags & LOOKUP_PARENT);
    return retval;
}

static int do_path_lookup(int dfd, const char *name,
            unsigned int flags, struct nameidata *nd)
{
    struct filename filename = {.name = name};

    return filename_lookup(dfd, &filename, flags, nd);
}

struct dentry *kern_path_locked(const char *name, struct path *path)
{
    struct nameidata nd;
    struct dentry *d;
    int err = do_path_lookup(AT_FDCWD, name, LOOKUP_PARENT, &nd);
    if (err)
        return ERR_PTR(err);
    if (nd.last_type != LAST_NORM) {
        path_put(&nd.path);
        return ERR_PTR(-EINVAL);
    }
    mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, IMUTEX_PARENT);
    d = __lookup_hash(&nd.last, nd.path.dentry, 0);
    if (IS_ERR(d)) {
        mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
        path_put(&nd.path);
        return d;
    }
    *path = nd.path;
    return d;
}

struct s_dentry *__d_lookup_rcu(const struct s_dentry *parent,
            const struct s_qstr *name,
            unsigned *seqp, struct inode *inode)
{
    u64 hashlen = name->hash_len;
    const unsigned char *str = name->name;
    struct hlist_bl_head *b = d_hash(parent, hashlen_hash(hashlen));
    struct hlist_bl_node *node;
    struct s_dentry *dentry;

    hlist_bl_for_each_entry_rcu(dentry, node, b, s_hash) {
        unsigned seq;

seqretry:
        seq = raw_seqcount_begin(&dentry->s_seq);
        if (dentry->s_parent != parent)
            continue;
        if (d_unhashed(dentry))
            continue;
        *seqp = seq;

        if (dentry->s_name.hash_len != hashlen)
            continue;
        if (!dentry_cmp(dentry, str, hashlen_len(hashlen)))
            return dentry;
    }
    return NULL;
}

struct s_dentry *s_lookup(const struct s_dentry *parent, const struct s_qstr *name)
{
    struct s_dentry *dentry;
    unsigned seq;

    do {
        seq = read_seqbegin(&rename_lock);
        dentry = __s_lookup(parent, name);
        if (dentry)
            break;
    } while (read_seqretry(&rename_lock, seq));
    return dentry;
}

#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

static inline int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
    unsigned long a,b,mask;

    for (;;) {
        a = *(unsigned long *)cs;
        b = load_unalingned_zeropad(ct);
        if (tcount < sizeof(unsigned long))
            break;
        if (unlikely(a != b))
            return 1;
        cs += sizeof(unsigned long);
        ct += sizeof(unsigned long);
        tcount -= sizeof(unsigned long);
        if (!tcount)
            return 0;
    }
    mask = ~(~0ul << tcount*8);
    return unlikely(!!((a ^ b) & mask));
}

#else

static inline int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
    do {
        if (*cs != *ct)
            return 1;
        cs++;
        ct++;
        tcount--;
    } while (tcount);
    return 0;
}

#endif

static inline int dentry_cmp(const struct dentry *dentry, const unsigned char *ct, unsigned tcount)
{
    const unsigned char *cs;

    cs = ACCESS_ONCE(dentry->s_name.name);
    smp_read_barrier_depends();
    return dentry_string_cmp(cs, ct, tcount);
}

struct s_dentry *__s_lookup(const struct s_dentry *parent, const struct s_qstr *name)
{
    unsigned int len = name->len;
    unsigned int hash = name->hash;
    const unsigned char *str = name->name;
    struct hlist_bl_head *b = d_hash(parent, hash);
    struct hlist_bl_node *node;
    struct s_dentry *found = NULL;
    struct s_dentry *dentry;

    rcu_read_lock();

    hlist_bl_for_each_entry_rcu(s_dentry, node, b, s_hash) {
        if (dentry->s_name.hash != hash)
            continue;

        spin_lock(&dentry->s_lock);
        if (dentry->s_parent != parent)
            goto next;
        if (d_unhashed(dentry))
            goto next;

        if (dentry->s_name.len != len)
            goto next;
        if (dentry_cmp(dentry, str, len))
            goto next;

        dentry->s_count++;
        found = dentry;
        spin_unlock(&dentry->s_lock);
        break;

next:
        spin_unlock(&dentry->s_lock);
    }
    rcu_read_unlock();

    return found;
}

struct s_dentry *d_hash_and_lookup(struct s_dentry *dir, struct s_qstr *name)
{
    name->hash = s_full_name_hash(name->name, name->len);
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
                    &s_hash_shift,
                    &s_hash_mask,
                    0,
                    0);

    for (loop = 0; loop < (1U << s_hash_shift); loop++)
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
                    &s_hash_shift,
                    &s_hash_mask,
                    0,
                    0);

    for (loop = 0; loop < (1U << s_hash_shift); loop++)
        INIT_HLIST_BL_HEAD(dentry_hashtable + loop);
}
