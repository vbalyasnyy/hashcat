/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_MD5_H
#define _INC_HASH_MD5_H

#define MD5_F_S(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G_S(x,y,z)  ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H_S(x,y,z)  ((x) ^ (y) ^ (z))
#define MD5_I_S(x,y,z)  ((y) ^ ((x) | ~(z)))

#define MD5_F(x,y,z)    ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x,y,z)    ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD5_H1(x,y,z)   ((t = (x) ^ (y)) ^ (z))
#define MD5_H2(x,y,z)   ((x) ^ t)
#define MD5_I(x,y,z)    ((y) ^ ((x) | ~(z)))

#ifdef USE_BITSELECT
#define MD5_Fo(x,y,z)   (bitselect ((z), (y), (x)))
#define MD5_Go(x,y,z)   (bitselect ((y), (x), (z)))
#else
#define MD5_Fo(x,y,z)   (MD5_F((x), (y), (z)))
#define MD5_Go(x,y,z)   (MD5_G((x), (y), (z)))
#endif

#define MD5_STEP_S(f,a,b,c,d,x,K,s)   \
{                                     \
  a += K;                             \
  a  = hc_add3_S (a, x, f (b, c, d)); \
  a  = hc_rotl32_S (a, s);            \
  a += b;                             \
}

#define MD5_STEP(f,a,b,c,d,x,K,s)   \
{                                   \
  a += K;                           \
  a  = hc_add3 (a, x, f (b, c, d)); \
  a  = hc_rotl32 (a, s);            \
  a += b;                           \
}

#define MD5_STEP0(f,a,b,c,d,K,s)    \
{                                   \
  a  = hc_add3 (a, K, f (b, c, d)); \
  a  = hc_rotl32 (a, s);            \
  a += b;                           \
}

#define hc_add3_S(a,b,c) (a + b + c)
#define hc_rotl32_S(a,n) ((a << n) | (a >> (32 - n)))



typedef struct md5_ctx
{
  u32 h[4];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} md5_ctx_t;

typedef struct md5_hmac_ctx
{
  md5_ctx_t ipad;
  md5_ctx_t opad;

} md5_hmac_ctx_t;

void md5_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);

#define append_helper_1x4_S_(r,v,m)	\
  r[0] |= v & m[0];			\
  r[1] |= v & m[1];			\
  r[2] |= v & m[2];			\
  r[3] |= v & m[3];

#define set_mark_1x4_S_(v,offset)		\
{						\
  const u32 c = (offset & 15) / 4;		\
  const u32 r = 0xff << ((offset & 3) * 8);	\
						\
  v[0] = (c == 0) ? r : 0;			\
  v[1] = (c == 1) ? r : 0;			\
  v[2] = (c == 2) ? r : 0;			\
  v[3] = (c == 3) ? r : 0;			\
}

#define append_0x80_4x4_S_(w0,w1,w2,w3,offset)	\
{						\
  u32 v[4];					\
						\
  set_mark_1x4_S_ (v, offset);			\
						\
  const u32 offset16 = offset / 16;		\
						\
  append_helper_1x4_S_ (w0, ((offset16 == 0) ? 0x80808080 : 0), v);	\
  append_helper_1x4_S_ (w1, ((offset16 == 1) ? 0x80808080 : 0), v);	\
  append_helper_1x4_S_ (w2, ((offset16 == 2) ? 0x80808080 : 0), v);	\
  append_helper_1x4_S_ (w3, ((offset16 == 3) ? 0x80808080 : 0), v);	\
}

#define md5_init(ctx)   \
{                       \
  ctx.h[0] = MD5M_A;    \
  ctx.h[1] = MD5M_B;    \
  ctx.h[2] = MD5M_C;    \
  ctx.h[3] = MD5M_D;    \
                        \
  ctx.w0[0] = 0;        \
  ctx.w0[1] = 0;        \
  ctx.w0[2] = 0;        \
  ctx.w0[3] = 0;        \
  ctx.w1[0] = 0;        \
  ctx.w1[1] = 0;        \
  ctx.w1[2] = 0;        \
  ctx.w1[3] = 0;        \
  ctx.w2[0] = 0;        \
  ctx.w2[1] = 0;        \
  ctx.w2[2] = 0;        \
  ctx.w2[3] = 0;        \
  ctx.w3[0] = 0;        \
  ctx.w3[1] = 0;        \
  ctx.w3[2] = 0;        \
  ctx.w3[3] = 0;        \
                        \
  ctx.len = 0;          \
}

void md5_update_64 (md5_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
void md5_update (md5_ctx_t *ctx, const u32 *w, const int len);
void md5_final (md5_ctx_t *ctx);
void md5_hmac_init_64 (md5_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
void md5_hmac_init (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
void md5_hmac_update_64 (md5_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
void md5_hmac_update (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
void md5_hmac_final (md5_hmac_ctx_t *ctx);
#endif
