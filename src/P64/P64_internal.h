/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: internal header file for P64
*********************************************************************************************/  

#ifndef __P64_INTERNAL_H__
#define __P64_INTERNAL_H__

#include "../config.h"
 

#if (TARGET == TARGET_AMD64) || (TARGET == TARGET_ARM64)
    #define NWORDS_FIELD   1               // Number of words of a 64-bit field element
    #define p64_ZERO_WORDS 0               // Number of "0" digits in the least significant part of p64 + 1
#endif


// Basic constants

#ifdef p_22_15 
    #define NBITS_FIELD 46
#else
    #error "Selected prime is not supported... "
#endif

#define MAXBITS_FIELD           64                
#define MAXWORDS_FIELD          ((MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD          ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 64-bit field element 
#define NBITS_ORDER             64
#define NWORDS_ORDER            ((NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER          ((NBITS_ORDER+63)/64)               // Number of 64-bit words of a 256-bit element 
#define MAXBITS_ORDER           NBITS_ORDER                         
#define MAXWORDS_ORDER          ((MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, oA-1] or [1, oB].
#define ALICE                   0
#define BOB                     1 
#define OALICE_BITS             32 // CHECK TODO
#define OBOB_BITS               32 
#define PRIME                   p64 
#define PARAM_A                 6  
#define PARAM_C                 1
// Fixed parameters for isogeny tree computation
#define MAX_INT_POINTS_ALICE    7
#define FP2_ENCODED_BYTES       2*((NBITS_FIELD + 7) / 8)


// SIDH's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];                                 // Datatype for representing 64-bit field elements (512-bit max.)
typedef digit_t dfelm_t[2*NWORDS_FIELD];                              // Datatype for representing double-precision 2x64-bit field elements (512-bit max.) 
typedef felm_t  f2elm_t[2];                                           // Datatype for representing quadratic extension field elements GF(p64^2)
        
typedef struct { f2elm_t X; f2elm_t Z; } point_proj;                  // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1]; 



/**************** Function prototypes ****************/
/************* Multiprecision functions **************/ 

// Copy wordsize digits, c = a, where lng(a) = nwords
void copy_words(const digit_t* a, digit_t* c, const unsigned int nwords);

// Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
unsigned int mp_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

// 64-bit multiprecision addition, c = a+b
// void mp_add64(const digit_t* a, const digit_t* b, digit_t* c);
void mp_add64_asm(const digit_t* a, const digit_t* b, digit_t* c); 

// Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit 
unsigned int mp_sub(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords); 

// 2x64-bit multiprecision subtraction followed by addition with p64*2^64, c = a-b+(p64*2^64) if a-b < 0, otherwise c=a-b 
void mp_subaddx2_asm(const digit_t* a, const digit_t* b, digit_t* c);
void mp_subadd64x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Double 2x64-bit multiprecision subtraction, c = c-a-b, where c > a and c > b
void mp_dblsub64x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Multiprecision left shift
void mp_shiftleft(digit_t* x, unsigned int shift, const unsigned int nwords);

// Multiprecision right shift by one
void mp_shiftr1(digit_t* x, const unsigned int nwords);

// Multiprecision left right shift by one    
void mp_shiftl1(digit_t* x, const unsigned int nwords);

// Digit multiplication, digit * digit -> 2-digit result
// void digit_x_digit(const digit_t a, const digit_t b, digit_t* c); 

// Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
void fpcopy64(const digit_t* a, digit_t* c);

// Zeroing a field element, a = 0
void fpzero64(digit_t* a);

// Modular addition, c = a+b mod p64
extern void fpadd64(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpadd64_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular subtraction, c = a-b mod p64
extern void fpsub64(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpsub64_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular negation, a = -a mod p64        
extern void fpneg64(digit_t* a);  

// Modular division by two, c = a/2 mod p64.
void fpdiv2_64(const digit_t* a, digit_t* c);

// Modular correction to reduce field element a in [0, 2*p64-1] to [0, p64-1].
void fpcorrection64(digit_t* a);

// 64-bit Montgomery reduction, c = a mod p
void rdc_mont(digit_t* a, digit_t* c);
void rdc64_asm(digit_t* ma, digit_t* mc);
            
// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p64, where R=2^768
void fpmul64_mont(const digit_t* a, const digit_t* b, digit_t* c);
void mul64_asm(const digit_t* a, const digit_t* b, digit_t* c);
   
// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p64, where R=2^768
void fpsqr64_mont(const digit_t* ma, digit_t* mc);

// Conversion to Montgomery representation
void to_mont(const digit_t* a, digit_t* mc);
    
// Conversion from Montgomery representation to standard representation
void from_mont(const digit_t* ma, digit_t* c);

// Field inversion, a = a^-1 in GF(p64)
void fpinv64_mont(digit_t* a);

/************ GF(p^2) arithmetic functions *************/

// Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
void fp2_encode(const f2elm_t x, unsigned char *enc);

// Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
void fp2_decode(const unsigned char *enc, f2elm_t x);

// Is a = b? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
bool fp2_is_equal(const f2elm_t a, const f2elm_t b);
    
// Copy of a GF(p64^2) element, c = a
void fp2copy64(const f2elm_t a, f2elm_t c);

// Zeroing a GF(p64^2) element, a = 0
void fp2zero64(f2elm_t a);

// GF(p64^2) negation, a = -a in GF(p64^2)
void fp2neg64(f2elm_t a);

// GF(p64^2) addition, c = a+b in GF(p64^2)
void fp2add64(const f2elm_t a, const f2elm_t b, f2elm_t c);           

// GF(p64^2) subtraction, c = a-b in GF(p64^2)
void fp2sub64(const f2elm_t a, const f2elm_t b, f2elm_t c); 

// GF(p64^2) division by two, c = a/2  in GF(p64^2) 
void fp2div2_64(const f2elm_t a, f2elm_t c);

// Modular correction, a = a in GF(p64^2)
void fp2correction64(f2elm_t a);
            
// GF(p64^2) squaring using Montgomery arithmetic, c = a^2 in GF(p64^2)
void fp2sqr64_mont(const f2elm_t a, f2elm_t c);
 
// GF(p64^2) multiplication using Montgomery arithmetic, c = a*b in GF(p64^2)
void fp2mul64_mont(const f2elm_t a, const f2elm_t b, f2elm_t c);
    
// Conversion of a GF(p64^2) element to Montgomery representation
void to_fp2mont(const f2elm_t a, f2elm_t mc);

// Conversion of a GF(p64^2) element from Montgomery representation to standard representation
void from_fp2mont(const f2elm_t ma, f2elm_t c);

// GF(p64^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv64_mont(f2elm_t a);

/************ Elliptic curve and isogeny functions *************/

// Computes the j-invariant of a Montgomery curve with projective constant.
void j_inv(const f2elm_t A, const f2elm_t C, f2elm_t jinv);

// Simultaneous doubling and differential addition.
void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t xPQ, const f2elm_t A24);

// Doubling of a Montgomery point in projective coordinates (X:Z).
void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24, const int e);

// Differential addition.
void xADD(point_proj_t Q, const point_proj_t P, const f2elm_t xPQ, const f2elm_t A24);

// Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
void get_4_isog(const point_proj_t P, f2elm_t A24plus, f2elm_t C24, f2elm_t* coeff);

// Evaluates the isogeny at the point (X:Z) in the domain of the isogeny.
void eval_4_isog(point_proj_t P, f2elm_t* coeff);

// Tripling of a Montgomery point in projective coordinates (X:Z).
void xTPL(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus);

// Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
void xTPLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus, const int e);

// Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
void get_3_isog(const point_proj_t P, f2elm_t A24minus, f2elm_t A24plus, f2elm_t* coeff);

// Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and a point P with coefficients given in coeff.
void eval_3_isog(point_proj_t Q, const f2elm_t* coeff);

// 3-way simultaneous inversion
void inv_3_way(f2elm_t z1, f2elm_t z2, f2elm_t z3);

// Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
void get_A(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xR, f2elm_t A);


#endif