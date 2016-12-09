#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include <linux/seqlock.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/rcuupdate.h>

#define S_IS_ROOT(x) ((x) == (x)->s_parent)

#ifdef __LITTLE_ENDIAN
 #define S_HASH_LEN_DECLARE u32 hash; u32 len;
#else
 #define S_HASH_LEN_DECLARE u32 len; u32 hash;
#endif

struct s_qstr {
    union {
        struct {
            HASH_LEN_DECLARE
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

#define S_QSTR_INIT(n, l) { { { .len = l } }, .name = n }
#define s_hashlen_hash(hashlen) ((u32) (hashlen))
#define s_hashlen_len(hashlen) ((u32)((hashlen) >> 32))

#define s_init_name_hash()    0

static inline unsigned long
s_partial_name_hash(unsigned long c, unsigned long prevhash)
{
    return (prevhash + (c << 4) + (c >> 4)) * 11;
}

static inline unsigned long s_end_name_hash(unsigned long hash)
{
    return (unsigned int) hash;
}

struct s_dentry {
    unsigned int s_action;
    seqcount_t d_seq;
    struct hlist_bl_node s_hash;
    struct s_dentry *s_parent;
    struct s_qstr s_name;

    unsigned int s_count;
    spinlock_t s_lock;
    struct list_head s_child;
    struct list_head s_subdirs;
    struct rcu_head d_rcu;
}

struct s_user {
    spinlock_t s_user_lock;
    kuid_t s_uid;
    char *s_user_name;
    s_dentry *user_root_dentry;
    struct hlist_bl_head *user_s_dentry_hashtable __read_mostly;
}

#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

#ifdef CONFIG_64BIT

static inline unsigned int fold_hash(unsigned long hash)
{
    return hash_64(hash, 32);
}

#else

#define fold_hash(x) (x)

#endif

unsigned int full_name_hash(const unsigned char *name, unsigned int len)
{
    unsigned long a, mask;
    unsigned long hash = 0;

    for (;;) {
        a = load_unaligned_zeropad(name);
        if (len < sizeof(unsigned long))
            break;
        hash += a;
        hash *= 9;
        name += sizeof(unsigned long);
        len -= sizeof(unsigned long);
        if (!len)
            goto done;
    }
    mask = ~(~0ul << len*8);
    hash += mask & a;
done:
    return fold_hash(hash);
}

static inline unsigned long hash_name(const char *name, unsigned int *hashp)
{
    unsigned long a, b, adata, bdata, mask, hash, len;
    const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

    hash = a = 0;
    len = -sizeof(unsigned long);
    do {
        hash = (hash + a) * 9;
        len += sizeof(unsigned long);
        a = load_unaligned_zeropad(name+len);
        b = a ^ REPEAT_BYTE('/');
    } while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

    adata = prep_zero_mask(a, adata, &constants);
    bdata = prep_zero_mask(b, bdata, &constants);

    mask = create_zero_mask(adata | bdata);
    hash += a & zero_bytemask(mask);
    *hashp = fold_hash(hash);

    return len + find_zero(mask);
}

#else

unsigned int full_name_hash(const unsigned char *name, unsigned int len)
{
    unsigned long hash = init_name_hash();
    while (len--)
        hash = partial_name_hash(*name++, hash);
    return end_name_hash(hash);
}

static inline unsigned long hash_name(const char *name, unsigned int *hashp)
{
    unsigned long hash = init_name_hash();
    unsigned long len = 0, c;

    c = (unsigned char)*name;
    do {
        len++;
        hash = partial_name_hash(c, hash);
        c = (unsigned char)name[len];
    } while (c && c != '/');
    *hashp = end_name_hash(hash);
    return len;
}

#endif
