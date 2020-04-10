#ifndef _MUSIG_H_

#define _MUSIG_H_

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
#define MuSig_DEBUG 0 /* 1 for debug ; 0 for release */

typedef nn MuSig_privkey;
typedef MuSig_privkey* MuSig_privkey_t;

typedef prj_pt MuSig_pubkey;
typedef MuSig_pubkey* MuSig_pubkey_t;

typedef struct{
    MuSig_privkey privk;
    MuSig_pubkey pubk;
} MuSig_keypair;

typedef struct{
    ec_params* params;
    u32 signers,trecvs,srecvs;
    u32 Rrecv[MAX_SIGNERS];
    nn r;
    prj_pt Pi_R;
    prj_pt agg_X;
    MuSig_keypair kpair;
    MuSig_pubkey pubklist[MAX_SIGNERS];
    prj_pt Rlist[MAX_SIGNERS];
    u8 tlist[MAX_SIGNERS][32];
    nn a;
    nn s[MAX_SIGNERS];
    char* message;
    u32 len;
} MuSig_context;

typedef MuSig_context* MuSig_context_t;
typedef MuSig_keypair* MuSig_keypair_t;

/* random generate MuSig key pair */
int MuSig_key_pair_gen(MuSig_keypair_t kpair,ec_params *in_str_params);

/* pubklist is a arrary which length is signers ,containing the public key in keypair. */
int MuSig_context_init(
    MuSig_context_t ctx,
    ec_params* in_params,
    MuSig_keypair_t kpair,
    MuSig_pubkey_t pubklist,
    u32 signers,
    char* message,
    u32 len);

int MuSig_sign_send_t(MuSig_context_t ctx,u8 out_t[32]);
int MuSig_sign_recv_t(MuSig_context_t ctx,u8 in_t[32]);
int MuSig_sign_send_R(MuSig_context_t ctx,u8 out_t[32],prj_pt_t out_R);
int MuSig_sign_recv_R(MuSig_context_t ctx,u8 in_t[32],prj_pt_t in_R);
int MuSig_sign_send_s(MuSig_context_t ctx,nn_t out_s);
int MuSig_sign_recv_s(MuSig_context_t ctx,nn_t in_s);

/* this function should be used after receive partial signature s and before BN_sign_recv_s, see more details in README.md */
int MuSig_sign_SignInCheck(MuSig_context_t ctx,nn_t si,MuSig_pubkey_t verkey,prj_pt_t Ri);

int MuSig_sign_finalize(MuSig_context_t ctx,prj_pt_t R,nn_t s);

/* return 1 meaning verify successful ;otherwise meaning refuse this signature*/
int MuSig_verify(ec_params* in_params,MuSig_pubkey_t pubk,u32 signers,prj_pt_t R,nn_t s,char* messsage,u32 len);

void char2nn(char* string,u32 strlen,nn_t out);
void prj2buf(prj_pt_t prj,u8 buf[32*2]);
void H_com(prj_pt_t x,u8 y[32]);
void H_agg(prj_pt_t in,prj_pt_t inlist,u32 prjlen,nn_t out);
void H_sig(prj_pt_t in1,prj_pt_t in2,char* m, u32 mlen,nn_t out);

#endif