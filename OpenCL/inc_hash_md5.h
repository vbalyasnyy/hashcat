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

#define md5_init(ctx)			\
{					\
  ctx.h[0] = MD5M_A;			\
  ctx.h[1] = MD5M_B;			\
  ctx.h[2] = MD5M_C;			\
  ctx.h[3] = MD5M_D;			\
					\
  ctx.w0[0] = 0;			\
  ctx.w0[1] = 0;			\
  ctx.w0[2] = 0;			\
  ctx.w0[3] = 0;			\
  ctx.w1[0] = 0;			\
  ctx.w1[1] = 0;			\
  ctx.w1[2] = 0;			\
  ctx.w1[3] = 0;			\
  ctx.w2[0] = 0;			\
  ctx.w2[1] = 0;			\
  ctx.w2[2] = 0;			\
  ctx.w2[3] = 0;			\
  ctx.w3[0] = 0;			\
  ctx.w3[1] = 0;			\
  ctx.w3[2] = 0;			\
  ctx.w3[3] = 0;			\
					\
  ctx.len = 0;				\
}

#define md5_hmac_final(ctx)		\
{					\
  md5_final (ctx.ipad);			\
					\
  ctx.opad.w0[0] = ctx.ipad.h[0];	\
  ctx.opad.w0[1] = ctx.ipad.h[1];	\
  ctx.opad.w0[2] = ctx.ipad.h[2];	\
  ctx.opad.w0[3] = ctx.ipad.h[3];	\
  ctx.opad.w1[0] = 0;			\
  ctx.opad.w1[1] = 0;			\
  ctx.opad.w1[2] = 0;			\
  ctx.opad.w1[3] = 0;			\
  ctx.opad.w2[0] = 0;			\
  ctx.opad.w2[1] = 0;			\
  ctx.opad.w2[2] = 0;			\
  ctx.opad.w2[3] = 0;			\
  ctx.opad.w3[0] = 0;			\
  ctx.opad.w3[1] = 0;			\
  ctx.opad.w3[2] = 0;			\
  ctx.opad.w3[3] = 0;			\
					\
  ctx.opad.len += 16;			\
					\
  md5_final (ctx.opad);			\
}

#define md5_final(ctx)						\
{								\
  const int pos = ctx.len & 63;					\
								\
  append_0x80_4x4_S_ (ctx.w0, ctx.w1, ctx.w2, ctx.w3, pos);	\
								\
  if (pos >= 56)						\
  {								\
    md5_transform (ctx.w0, ctx.w1, ctx.w2, ctx.w3, ctx.h);	\
								\
    ctx.w0[0] = 0;						\
    ctx.w0[1] = 0;						\
    ctx.w0[2] = 0;						\
    ctx.w0[3] = 0;						\
    ctx.w1[0] = 0;						\
    ctx.w1[1] = 0;						\
    ctx.w1[2] = 0;						\
    ctx.w1[3] = 0;						\
    ctx.w2[0] = 0;						\
    ctx.w2[1] = 0;						\
    ctx.w2[2] = 0;						\
    ctx.w2[3] = 0;						\
    ctx.w3[0] = 0;						\
    ctx.w3[1] = 0;						\
    ctx.w3[2] = 0;						\
    ctx.w3[3] = 0;						\
  }								\
								\
  ctx.w3[2] = ctx.len * 8;					\
  ctx.w3[3] = 0;						\
								\
  md5_transform (ctx.w0, ctx.w1, ctx.w2, ctx.w3, ctx.h);	\
}

#define md5_transform(w0,w1,w2,w3,digest)			\
{								\
  u32 a = digest[0];						\
  u32 b = digest[1];						\
  u32 c = digest[2];						\
  u32 d = digest[3];						\
								\
  u32 w0_t = w0[0];						\
  u32 w1_t = w0[1];						\
  u32 w2_t = w0[2];						\
  u32 w3_t = w0[3];						\
  u32 w4_t = w1[0];						\
  u32 w5_t = w1[1];						\
  u32 w6_t = w1[2];						\
  u32 w7_t = w1[3];						\
  u32 w8_t = w2[0];						\
  u32 w9_t = w2[1];						\
  u32 wa_t = w2[2];						\
  u32 wb_t = w2[3];						\
  u32 wc_t = w3[0];						\
  u32 wd_t = w3[1];						\
  u32 we_t = w3[2];						\
  u32 wf_t = w3[3];						\
								\
  MD5_STEP_S (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);	\
  MD5_STEP_S (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);	\
  MD5_STEP_S (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);	\
  MD5_STEP_S (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);	\
  MD5_STEP_S (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);	\
  MD5_STEP_S (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);	\
  MD5_STEP_S (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);	\
  MD5_STEP_S (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);	\
  MD5_STEP_S (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);	\
  MD5_STEP_S (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);	\
  MD5_STEP_S (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);	\
  MD5_STEP_S (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);	\
  MD5_STEP_S (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);	\
  MD5_STEP_S (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);	\
  MD5_STEP_S (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);	\
  MD5_STEP_S (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);	\
								\
  MD5_STEP_S (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);	\
  MD5_STEP_S (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);	\
  MD5_STEP_S (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);	\
  MD5_STEP_S (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);	\
  MD5_STEP_S (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);	\
  MD5_STEP_S (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);	\
  MD5_STEP_S (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);	\
  MD5_STEP_S (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);	\
  MD5_STEP_S (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);	\
  MD5_STEP_S (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);	\
  MD5_STEP_S (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);	\
  MD5_STEP_S (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);	\
  MD5_STEP_S (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);	\
  MD5_STEP_S (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);	\
  MD5_STEP_S (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);	\
  MD5_STEP_S (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);	\
								\
  u32 t;							\
								\
  MD5_STEP_S (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);	\
  MD5_STEP_S (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);	\
  MD5_STEP_S (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);	\
  MD5_STEP_S (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);	\
  MD5_STEP_S (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);	\
  MD5_STEP_S (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);	\
  MD5_STEP_S (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);	\
  MD5_STEP_S (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);	\
  MD5_STEP_S (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);	\
  MD5_STEP_S (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);	\
  MD5_STEP_S (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);	\
  MD5_STEP_S (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);	\
  MD5_STEP_S (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);	\
  MD5_STEP_S (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);	\
  MD5_STEP_S (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);	\
  MD5_STEP_S (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);	\
								\
  MD5_STEP_S (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);	\
  MD5_STEP_S (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);	\
  MD5_STEP_S (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);	\
  MD5_STEP_S (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);	\
  MD5_STEP_S (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);	\
  MD5_STEP_S (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);	\
  MD5_STEP_S (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);	\
  MD5_STEP_S (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);	\
  MD5_STEP_S (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);	\
  MD5_STEP_S (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);	\
  MD5_STEP_S (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);	\
  MD5_STEP_S (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);	\
  MD5_STEP_S (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);	\
  MD5_STEP_S (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);	\
  MD5_STEP_S (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);	\
  MD5_STEP_S (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);	\
								\
  digest[0] += a;						\
  digest[1] += b;						\
  digest[2] += c;						\
  digest[3] += d;						\
}

#define md5_update_64(ctx,W0,W1,W2,W3,LEN)			\
{								\
  ctx.len += LEN;						\
								\
  ctx.w0[0] = W0[0];						\
  ctx.w0[1] = W0[1];						\
  ctx.w0[2] = W0[2];						\
  ctx.w0[3] = W0[3];						\
  ctx.w1[0] = W1[0];						\
  ctx.w1[1] = W1[1];						\
  ctx.w1[2] = W1[2];						\
  ctx.w1[3] = W1[3];						\
  ctx.w2[0] = W2[0];						\
  ctx.w2[1] = W2[1];						\
  ctx.w2[2] = W2[2];						\
  ctx.w2[3] = W2[3];						\
  ctx.w3[0] = W3[0];						\
  ctx.w3[1] = W3[1];						\
  ctx.w3[2] = W3[2];						\
  ctx.w3[3] = W3[3];						\
								\
  if (LEN == 64)						\
  {								\
    md5_transform (ctx.w0, ctx.w1, ctx.w2, ctx.w3, ctx.h);	\
								\
    ctx.w0[0] = 0;						\
    ctx.w0[1] = 0;						\
    ctx.w0[2] = 0;						\
    ctx.w0[3] = 0;						\
    ctx.w1[0] = 0;						\
    ctx.w1[1] = 0;						\
    ctx.w1[2] = 0;						\
    ctx.w1[3] = 0;						\
    ctx.w2[0] = 0;						\
    ctx.w2[1] = 0;						\
    ctx.w2[2] = 0;						\
    ctx.w2[3] = 0;						\
    ctx.w3[0] = 0;						\
    ctx.w3[1] = 0;						\
    ctx.w3[2] = 0;						\
    ctx.w3[3] = 0;						\
  }								\
}

#define md5_hmac_init_64(ctx,w0,w1,w2,w3)			\
{								\
  u32 t0[4];							\
  u32 t1[4];							\
  u32 t2[4];							\
  u32 t3[4];							\
								\
  t0[0] = w0[0] ^ 0x36363636;					\
  t0[1] = w0[1] ^ 0x36363636;					\
  t0[2] = w0[2] ^ 0x36363636;					\
  t0[3] = w0[3] ^ 0x36363636;					\
  t1[0] = w1[0] ^ 0x36363636;					\
  t1[1] = w1[1] ^ 0x36363636;					\
  t1[2] = w1[2] ^ 0x36363636;					\
  t1[3] = w1[3] ^ 0x36363636;					\
  t2[0] = w2[0] ^ 0x36363636;					\
  t2[1] = w2[1] ^ 0x36363636;					\
  t2[2] = w2[2] ^ 0x36363636;					\
  t2[3] = w2[3] ^ 0x36363636;					\
  t3[0] = w3[0] ^ 0x36363636;					\
  t3[1] = w3[1] ^ 0x36363636;					\
  t3[2] = w3[2] ^ 0x36363636;					\
  t3[3] = w3[3] ^ 0x36363636;					\
								\
  md5_init (ctx.ipad);						\
								\
  md5_update_64 (ctx.ipad, t0, t1, t2, t3, 64);			\
								\
  t0[0] = w0[0] ^ 0x5c5c5c5c;					\
  t0[1] = w0[1] ^ 0x5c5c5c5c;					\
  t0[2] = w0[2] ^ 0x5c5c5c5c;					\
  t0[3] = w0[3] ^ 0x5c5c5c5c;					\
  t1[0] = w1[0] ^ 0x5c5c5c5c;					\
  t1[1] = w1[1] ^ 0x5c5c5c5c;					\
  t1[2] = w1[2] ^ 0x5c5c5c5c;					\
  t1[3] = w1[3] ^ 0x5c5c5c5c;					\
  t2[0] = w2[0] ^ 0x5c5c5c5c;					\
  t2[1] = w2[1] ^ 0x5c5c5c5c;					\
  t2[2] = w2[2] ^ 0x5c5c5c5c;					\
  t2[3] = w2[3] ^ 0x5c5c5c5c;					\
  t3[0] = w3[0] ^ 0x5c5c5c5c;					\
  t3[1] = w3[1] ^ 0x5c5c5c5c;					\
  t3[2] = w3[2] ^ 0x5c5c5c5c;					\
  t3[3] = w3[3] ^ 0x5c5c5c5c;					\
								\
  md5_init (ctx.opad);						\
								\
  md5_update_64 (ctx.opad, t0, t1, t2, t3, 64);			\
}

#endif
