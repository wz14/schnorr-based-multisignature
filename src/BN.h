#ifndef _BN_H_
#define _BN_H_

#include "libecc/src/lib_ecc_config.h"
#include "libecc/src/lib_ecc_types.h"

#include "libecc/src/nn/nn_rand.h"
#include "libecc/src/nn/nn_mul.h"
#include "libecc/src/nn/nn_logical.h"

#include "libecc/src/sig/sig_algs_internal.h"
#include "libecc/src/sig/ec_key.h"

#include "libecc/src/external_deps/print.h"
#include "libecc/src/external_deps/rand.h"
#include "libecc/src/external_deps/time.h"

#include "libecc/src/utils/print_nn.h"
#include "libecc/src/utils/print_fp.h"
#include "libecc/src/utils/print_curves.h"
#include "libecc/src/utils/utils.h"

#define MAX_SIGNERS 16
#define BN_DEBUG 0 /* 1 for debug ; 0 for release */

typedef nn BN_privkey;
typedef BN_privkey* BN_privkey_t;

typedef prj_pt BN_pubkey;
typedef BN_pubkey* BN_pubkey_t;

typedef struct{
    BN_privkey privk;
    BN_pubkey pubk;
} BN_keypair;

typedef struct{
    ec_params* params;
    u32 signers,trecvs,srecvs;
    u32 Rrecv[MAX_SIGNERS];
    nn r;
    prj_pt Pi_R;
    BN_keypair kpair;
    BN_pubkey pubklist[MAX_SIGNERS];
    prj_pt Rlist[MAX_SIGNERS];
    u8 tlist[MAX_SIGNERS][32];
    nn s[MAX_SIGNERS];
    char* message;
    u32 len;
} BN_context;

typedef BN_context* BN_context_t;
typedef BN_keypair* BN_keypair_t;

/* random generate BN key pair */
int BN_key_pair_gen(BN_keypair_t kpair,ec_params *in_str_params);

/* pubklist is a arrary which length is signers ,containing the public key in keypair. */
int BN_context_init(
    BN_context_t ctx,
    ec_params* in_params,
    BN_keypair_t kpair,
    BN_pubkey_t pubklist,
    u32 signers,
    char* message,
    u32 len);

int BN_sign_send_t(BN_context_t ctx,u8 out_t[32]);
int BN_sign_recv_t(BN_context_t ctx,u8 in_t[32]);
int BN_sign_send_R(BN_context_t ctx,u8 out_t[32],prj_pt_t out_R);
int BN_sign_recv_R(BN_context_t ctx,u8 in_t[32],prj_pt_t in_R);
int BN_sign_send_s(BN_context_t ctx,nn_t out_s);
int BN_sign_recv_s(BN_context_t ctx,nn_t in_s);

int BN_sign_finalize(BN_context_t ctx,prj_pt_t R,nn_t s);

/* return 1 meaning verify successful ;otherwise meaning refuse this signature*/
int BN_verify(ec_params* in_params,BN_pubkey_t pubk,u32 signers,prj_pt_t R,nn_t s,char* messsage,u32 len);

void char2nn(char* string,u32 strlen,nn_t out);
void prj2buf(prj_pt_t prj,u8 buf[32*2]);
void H1(prj_pt_t in1, prj_pt_t in2, prj_pt_t inlist, u32 prjlen, char* m, u32 mlen, nn_t out);
void H0(prj_pt_t x,u8 y[32]);

#endif