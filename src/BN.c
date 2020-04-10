#include "BN.h"

/* simulate raise exception in c++ */
void raise(char* msg,const char* location){
    ext_printf("[error]:%s in function:%s\n",msg,location);
}

/* raise x while a==-1 */
#define RAISE(x) do{ \
        raise(x,__FUNCTION__);\
}while(0)

/* from char* to nn */
void char2nn(char* string,u32 strlen,nn_t out){
    if(NN_MAX_BYTE_LEN<=strlen){
        nn_init_from_buf(out,string,NN_MAX_BYTE_LEN);
    }else{
        nn_init_from_buf(out,string,strlen);
    }
}
/* from prj_pt via aff_pt to buf */
void prj2buf(prj_pt_t prj,u8 buf[32*2]){
    aff_pt af;
    prj_pt_to_aff(&af,prj);
    fp_export_to_buf(buf,32,&(af.x));
    fp_export_to_buf(buf+32,32,&(af.y));
}

/* hash function h0 prj_pt to char[32] */
void H0(prj_pt_t x,u8 y[32]){
    u8 tmp[32*2];
    prj2buf(x,tmp);
    sha256(tmp,32*2,y);
}

/* hash function h1 <prj_pt||prj_pt||<List,Prj_pt>||char*>-><nn> */
void H1( prj_pt_t in1, prj_pt_t in2, prj_pt_t inlist, u32 prjlen, char* m, u32 mlen, nn_t out)
{
    u32 bytelen = SHA256_DIGEST_SIZE;
    u8 prjtmp[bytelen*2];
    u8 tmp[bytelen];
    sha256_context shactx;
    sha256_init(&shactx);
    prj2buf(in1,prjtmp);
    sha256_update(&shactx,prjtmp,bytelen*2);
    prj2buf(in2,prjtmp);
    sha256_update(&shactx,prjtmp,bytelen*2);
    for(int i=0;i<prjlen;i++){
        prj2buf(&(inlist[i]),prjtmp);
        sha256_update(&shactx,prjtmp,bytelen*2);
    }
    sha256_update(&shactx,m,mlen);
    sha256_final(&shactx,tmp);
    char2nn(tmp,bytelen,out);
    if(BN_DEBUG){ nn_print("h1 generate :",out); }
}

int BN_key_pair_gen(BN_keypair_t kpair, ec_params *in_params){
    int k;

    /* random choose x in order of generator g*/
	k = nn_get_random_mod(&(kpair->privk), &(in_params->ec_gen_order));
    if(BN_DEBUG){ nn_print("private key generate:",&(kpair->privk)); }
    if(k==-1){
        RAISE("random private key x");
        return -1;
    }
    prj_pt_src_t G = &(in_params->ec_gen);
    prj_pt_mul_monty(&(kpair->pubk), &(kpair->privk), G);
    if(BN_DEBUG){ ec_point_print("public key generate:",&(kpair->pubk)); }
    return 0;
}

int BN_context_init(BN_context_t ctx,ec_params* in_params,BN_keypair_t kpair_t,BN_pubkey_t pubklist,u32 signers,char* message,u32 len){
    ctx->params = in_params;
    ctx->signers = signers;
    ctx->trecvs = 0;
    ctx->srecvs = 0;
    for(int i=0;i<signers;i++){
        ctx->Rrecv[i] = 0;
    }
    /* copy message to ctx */
    ctx->message = message;
    ctx->len = len;
    /* copy keypair to context */
    nn_copy(&(ctx->kpair.privk),&(kpair_t->privk));
    prj_pt_copy(&(ctx->kpair.pubk),&(kpair_t->pubk));
    /* copy public key to context */
    int suc = -1;
    for(int i=0;i<signers;i++){
        prj_pt_copy(&(ctx->pubklist[i]),&(pubklist[i]));
        if(prj_pt_cmp(&(pubklist[i]),&(kpair_t->pubk))==0){
            suc = 0;
        }
    }
    if(suc!=0){
        RAISE("no public key in public key list");
    }
    return suc;
}

/* send t = H_0(t_i) to all other signers */
int BN_sign_send_t(BN_context_t ctx,u8 out_t[32]){
    ctx->Rrecv[0] = 1;
    ctx->trecvs = 1;
    /* random choice r */
    int k = nn_get_random_mod(&(ctx->r),&(ctx->params->ec_gen_order));
    if(BN_DEBUG){ nn_print("r generate:",&(ctx->r)); }
    if(k==-1){ 
        RAISE("generate r fail");
        return -1;
    }

    /* R = g^r */
    prj_pt_src_t G = &(ctx->params->ec_gen);
    prj_pt_mul_monty(&(ctx->Rlist[0]), &(ctx->r), G);
    if(BN_DEBUG){ ec_point_print("R generate:",&(ctx->Rlist[0])); }

    /* t = H0(R) */
    H0(&(ctx->Rlist[0]),ctx->tlist[0]);

    /* copy t to out_t */
    local_memcpy(out_t,ctx->tlist[0],32);

    return 0;
}

/* return -1 meaning in_t have been in ctx ,otherwise return 0*/
int BN_sign_recv_t(BN_context_t ctx,u8 in_t[32]){
    for(int i=0;i<ctx->trecvs;i++){
        if(are_equal(ctx->tlist[i],in_t,32)==1){
            return -1;
        }
    }
    if(ctx->trecvs>=ctx->signers){
        return -1;
    }
    local_memcpy(ctx->tlist[ctx->trecvs],in_t,32);
    ctx->trecvs += 1;
    return 0;
}

/* return 0 forever */
int BN_sign_send_R(BN_context_t ctx,u8 out_t[32],prj_pt_t out_R){
    local_memcpy(out_t,ctx->tlist[0],32);
    prj_pt_copy(out_R,&(ctx->Rlist[0]));
    return 0;
}

/* return -2 meaning we should abort this protocol */
int BN_sign_recv_R(BN_context_t ctx,u8 in_t[32],prj_pt_t in_R){
    u8 tmp[32];
    int i;
    for(i=0;i<ctx->trecvs;i++){
        if(are_equal(in_t,ctx->tlist[i],32)==1){
            if(ctx->Rrecv[i]==1){
                return -1;
            }
            H0(in_R,tmp);
            if(are_equal(tmp,in_t,32)!=1){
                RAISE("abort protocol!");
                return -2;
            }
            prj_pt_copy(&(ctx->Rlist[i]),in_R);
            ctx->Rrecv[i] = 1;
            return 0;
        }
    }
    RAISE("no such t in ctx");
    return -1;
}

/* return -1 meaning fail otherwise compute s and return 0 */
int BN_sign_send_s(BN_context_t ctx,nn_t s){
    /* check t,R */
    if(ctx->signers!=ctx->trecvs){
        return -1;
    }
    for(int i=0;i<ctx->signers;i++){
        if(ctx->Rrecv[i]!=1){
            return -1;
        }
    }
    /* Pi_R = \PI{R_i]} */
    prj_pt_copy(&(ctx->Pi_R),&(ctx->Rlist[0]));
    for(int i=1;i<ctx->signers;i++){
        prj_pt_add_monty(&(ctx->Pi_R),&(ctx->Pi_R),&(ctx->Rlist[i]));
    }
    
    /* c = H1(X_1||R||L||m) */
    nn c;
    H1(&(ctx->kpair.pubk),&(ctx->Pi_R),ctx->pubklist,ctx->signers,ctx->message,ctx->len,&c);
    /* s = x*c+r \mod p */
    nn_mul_mod(s,&c,&(ctx->kpair.privk),&(ctx->params->ec_gen_order));
    nn_mod_add(s,s,&(ctx->r),&(ctx->params->ec_gen_order));

    /* copy s to ctx */
    nn_copy(&(ctx->s[0]),s);

    ctx->srecvs = 1;
    nn_uninit(&c);
    return 0;
}

/* return -1 if s have included in ctx */
int BN_sign_recv_s(BN_context_t ctx,nn_t in_s){
    for(int i=0;i<ctx->srecvs;i++){
        if(nn_cmp(in_s,&(ctx->s[i]))==0){
            return -1;
        }
    }
    nn_copy(&(ctx->s[ctx->srecvs]),in_s);
    ctx->srecvs += 1;
    return 0;
}

int BN_sign_finalize(BN_context_t ctx,prj_pt_t R,nn_t s){
    if(ctx->signers!=ctx->srecvs){
        return -1;
    }
    /* add all s mod p*/
    nn_copy(s,&(ctx->s[0]));
    for(int i=1;i<ctx->srecvs;i++){
        nn_mod_add(s,s,&(ctx->s[i]),&(ctx->params->ec_gen_order));
    }
    
    /* copy Pi_R to output_R */
    prj_pt_copy(R,&(ctx->Pi_R));

    return 0;
}

/* return 1 meaning verify pass ;otherwise meaning refuse this signature*/
int BN_verify(ec_params* in_params,BN_pubkey_t pubk,u32 signers,prj_pt_t R,nn_t s,char* message,u32 len){
    nn c[signers];
    prj_pt left,right,tmp;
    for(int i=0;i<signers;i++){
        H1(&(pubk[i]),R,pubk,signers,message,len,&(c[i]));
    }
    /* left = g^s */
    prj_pt_mul_monty(&left,s,&(in_params->ec_gen));
    /* right = R*x_1^c_1*X_2^c_2..... */
    prj_pt_copy(&right,R);
    for(int i=0;i<signers;i++){
        prj_pt_mul_monty(&tmp,&(c[i]),&(pubk[i]));
        prj_pt_add_monty(&right,&right,&tmp);
    }
    if(prj_pt_cmp(&left,&right)==0){
        return 1;
    }
    return 0;
}