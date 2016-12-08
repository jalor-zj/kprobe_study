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
