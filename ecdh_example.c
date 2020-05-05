/*
  Diffie-Hellman key exchange (without HMAC) aka ECDH_anon in RFC4492


  1. Alice picks a (secret) random natural number 'a', calculates P = a * G and sends P to Bob.
     'a' is Alice's private key. 
     'P' is Alice's public key.

  2. Bob picks a (secret) random natural number 'b', calculates Q = b * G and sends Q to Alice.
     'b' is Bob's private key.
     'Q' is Bob's public key.

  3. Alice calculates S = a * Q = a * (b * G).

  4. Bob calculates T = b * P = b * (a * G).

  .. which are the same two values since multiplication in the field is commutative and associative.

  T = S = the new shared secret.


  Pseudo-random number generator inspired / stolen from: http://burtleburtle.net/bob/rand/smallprng.html

*/

//#include <// assert.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <time.h>
#include "ecdh.h"



/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
  u32 a;
  u32 b;
  u32 c;
  u32 d;
} prng_t;

static prng_t prng_ctx;

static u32 prng_rotate(u32 x, u32 k)
{
  return (x << k) | (x >> (32 - k)); 
}

static u32 prng_next(void)
{
  u32 e = prng_ctx.a - prng_rotate(prng_ctx.b, 27); 
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17); 
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; 
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

static void prng_init(u32 seed)
{
  u32 i;
  prng_ctx.a = 0xf1ea5eed;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i) 
  {
    (void) prng_next();
  }
}





static int ecdh_demo(void)
{
  static u8 puba[ECC_PUB_KEY_SIZE];
  static u8 prva[ECC_PRV_KEY_SIZE];
  static u8 seca[ECC_PUB_KEY_SIZE];
  static u8 pubb[ECC_PUB_KEY_SIZE];
  static u8 prvb[ECC_PRV_KEY_SIZE];
  static u8 secb[ECC_PUB_KEY_SIZE];
  u32 i;

  /* 0. Initialize and seed random number generator */
  static int initialized = 0;
  if (!initialized)
  {
    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
    initialized = 1;
  }

  /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
  {
    prva[i] = prng_next() ;
  }
  // assert(
  ecdh_generate_keys(puba, prva);
    //);

  /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
  {
    prvb[i] = prng_next();
  }
  // assert(
  ecdh_generate_keys(pubb, prvb);
    //);

  /* 3. Alice calculates S = a * Q = a * (b * g). */
  // assert(
  ecdh_shared_secret(prva, pubb, seca);
  //);

  /* 4. Bob calculates T = b * P = b * (a * g). */
  // assert(
  ecdh_shared_secret(prvb, puba, secb);
  //);
int k=0;
  /* 5. Assert equality, i.e. check that both parties calculated the same value. */
  for (i = 0; i < ECC_PUB_KEY_SIZE; ++i)
  {
    // assert(seca[i] == secb[i]);
    if(seca[i] != secb[i]){ k=1; };
  }
  return k;
}


/* WARNING: This is not working correctly. ECDSA is not working... */
void ecdsa_broken()
{
  static u8   prv[ECC_PRV_KEY_SIZE];
  static u32  pub[ECC_PUB_KEY_SIZE/4];
  static u8   msg[ECC_PRV_KEY_SIZE];
  static u32  signature[ECC_PUB_KEY_SIZE/4];
  static u8  k[ECC_PRV_KEY_SIZE];
  u32 i;

  //srand(time(0));
  //srand(42);  

  for (i = 0; i < ((CURVE_DEGREE/8)); ++i)
  {
        prv[i] = Random();
        msg[i] = prv[i] ^ Random();
        k[i] =   Random();
  }

 
//prv[0] =0x12345678; prv[1] =0xffffffff; prv[2] =0xffffffff; prv[3] =0x12345678; prv[4] =0x12345678;prv[5] =0x1;
//msg[0] =0x12345678; msg[1] =0x12345678; msg[2] =0x12345678; msg[3] =0x12345678; msg[4] =0x12345678;  msg[5] =0;
//k[0]   =0x12345678; k[1] =0x12345678; k[2] =0x12345678; k[3] =0x12345678; k[4] =0x12345678;  k[5] =0;
  
/* int ecdsa_sign(const u8* private, const u8* hash, u8* random_k, u8* signature);
   int ecdsa_verify(const u8* public, const u8* hash, u8* signature);                          */
start_timer();
  ecdh_generate_keys((u8*)pub, (u8*)prv);
 stop_timer(); 
 int kk=gf2point_on_curve((u32*)pub, (u32*)(pub + 6));

 /* No asserts - ECDSA functionality is broken... */
  ecdsa_sign((u32*)prv, (u32*)msg, (u32*)k, signature);
  ecdsa_verify(pub, (u32*)msg,  signature, (u32*)prv); /* fails... */
}


void chtest()
  {
   // ecdh_demo();

    
    
  //  start_timer();
    ecdsa_broken();
    ecdh_demo();
  //  stop_timer();
        

  }

int main_l(int argc, char* argv[])
{
  int i;
  int ncycles = 1;

  if (argc > 1)
  {
   // ncycles = atoi(argv[1]);
  }

  for (i = 0; i < ncycles; ++i)
  {
    ecdh_demo();
    ecdsa_broken();
  }

  return 0;
}


