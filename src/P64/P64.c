/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P64
*********************************************************************************************/  

#include "P64_internal.h"


// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located at the leftmost position (i.e., little endian format). 
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {a, b}, with a in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position. 
// Internally, the number of digits used to represent all these elements is obtained by approximating the number of bits to the immediately greater multiple of 32.
// For example, a 64-bit field element is represented with Ceil(64 / 64) = 1 64-bit digits or Ceil(64 / 32) = 2 32-bit digits.

//
// Curve isogeny system "SIDHp64". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p64^2), where A=0, B=1, C=1
//

/*
 * p64p1 = p64 + 1
 * p64x2 = 2*p64
 * Montgomery_rprime = -(p64)^-1 mod 2^64
 * Montgomery_R2 = (2^64)^2 mod p64
 * Montgomery_one = 2^64 mod p64
 */

#ifdef p_22_15
    /* p64 = 2^22*3^15 - 1 */
    const uint64_t p64[NWORDS64_FIELD] = {0x36BC9ABFFFFF};
    const uint64_t p64p1[NWORDS64_FIELD] = {0x36BC9AC00000};
    const uint64_t p64x2[NWORDS64_FIELD] = {0x6D79357FFFFE};
    const uint64_t Montgomery_rprime1[NWORDS64_ORDER] = {0xA78BC6BC9AC00001};
    const uint64_t Montgomery_R2[NWORDS64_ORDER] = {0x25512E2FF61A};
    const uint64_t Montgomery_one[NWORDS64_ORDER] = {0x172AE9C4AD4B};
#endif

// Setting up macro defines and including GF(p), GF(p^2), curve, isogeny and kex functions
#define fpcopy                        fpcopy64
#define fpzero                        fpzero64
#define fpadd                         fpadd64
#define fpsub                         fpsub64
#define fpneg                         fpneg64
#define fpdiv2                        fpdiv2_64
#define fpcorrection                  fpcorrection64
#define fpmul_mont                    fpmul64_mont
#define fpsqr_mont                    fpsqr64_mont
#define fpinv_mont                    fpinv64_mont
#define fpinv_chain_mont              fpinv64_chain_mont
#define fpinv_mont_bingcd             fpinv64_mont_bingcd
#define fp2copy                       fp2copy64
#define fp2zero                       fp2zero64
#define fp2add                        fp2add64
#define fp2sub                        fp2sub64
#define fp2neg                        fp2neg64
#define fp2div2                       fp2div2_64
#define fp2correction                 fp2correction64
#define fp2mul_mont                   fp2mul64_mont
#define fp2sqr_mont                   fp2sqr64_mont
#define fp2inv_mont                   fp2inv64_mont
#define fp2inv_mont_bingcd            fp2inv64_mont_bingcd
#define mp_add_asm                    mp_add64_asm
#define mp_subaddx2_asm               mp_subadd64x2_asm
#define mp_dblsubx2_asm               mp_dblsub64x2_asm
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp64
#define crypto_kem_enc                crypto_kem_enc_SIKEp64
#define crypto_kem_dec                crypto_kem_dec_SIKEp64
#define random_mod_order_A            random_mod_order_A_SIDHp64
#define random_mod_order_B            random_mod_order_B_SIDHp64

#include "../fpx.c"
#include "../ec_isogeny.c"