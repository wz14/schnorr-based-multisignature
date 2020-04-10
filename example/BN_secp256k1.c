#include "src/BN.h"
#define SIGNERS_N 5

int main(){
    int k;
    char message[] = "hello";
    u32 message_len = sizeof(message);
    ec_params ecparams;
    BN_keypair kpair[SIGNERS_N];
    BN_context ctx[SIGNERS_N];
    BN_pubkey pubklist[SIGNERS_N];
    prj_pt RList[SIGNERS_N];
    nn s[SIGNERS_N];
    u8 tlist[SIGNERS_N][32];
    /* signature storage */
    nn sig_s[SIGNERS_N];
    prj_pt sig_R[SIGNERS_N];

    /* import curve params */
    import_params(&(ecparams),&secp256k1_str_params);

    /* generate key pair for all signers */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_key_pair_gen(&(kpair[i]),&ecparams);
        if(k==-1){ ext_printf("key generate fail:%d \n",i); }
    }
    /* collect public keys of all signers */
    for(int i=0;i<SIGNERS_N;i++){
        prj_pt_copy(&(pubklist[i]),&(kpair[i].pubk));
    }

    /* init all signers */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_context_init(&(ctx[i]),&ecparams,&(kpair[i]),pubklist,SIGNERS_N,message,message_len);
        if(k==-1){ ext_printf("BN init context fail:%d \n",i); }
    }

    /* collect all t */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_sign_send_t(&(ctx[i]),tlist[i]);
        if(k==-1){ ext_printf("BN send t fail:%d\n",i); }
    }

    /* send t to all signers */
    for(int i=0;i<SIGNERS_N;i++){
        for(int j=0;j<SIGNERS_N;j++){
            if(i==j){
                continue;
            }
            k = BN_sign_recv_t(&(ctx[i]),tlist[j]);
            if(k==-1){ ext_printf("recv t fail in %d(t)->%d(ctx)\n",j,i); }
        }
    }

    /* collect all R */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_sign_send_R(&(ctx[i]),tlist[i],&(RList[i]));
        if(k==-1){ ext_printf("send R fail in %d\n",i); }
    }

    /* send all R to all signers */
    for(int i=0;i<SIGNERS_N;i++){
        for(int j=0;j<SIGNERS_N;j++){
            if(i==j){
                continue;
            }
            k = BN_sign_recv_R(&ctx[i],tlist[j],&(RList[j]));
            if(k==-1){ ext_printf("recv R fail in %d(t,R)->%d(ctx)\n",j,i); }
            if(k==-2){ 
                ext_printf("abort protocol in %d(t,R)->%d(ctx)\n",j,i); 
                return 0;
            }
        }
    }

    /* collect all s */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_sign_send_s(&(ctx[i]),&(s[i]));
        if(k==-1){ ext_printf("send s fail in %d\n",i); }
    }

    /* send all s to all signers */
    for(int i=0;i<SIGNERS_N;i++){
        for(int j=0;j<SIGNERS_N;j++){
            if(i==j){
                continue;
            }
            k = BN_sign_recv_s(&(ctx[i]),&(s[j]));
            if(k==-1){ ext_printf("recv s fail in %d(s)->%d(ctx)\n",j,i); }
        }
    }

    /* finalize all signers */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_sign_finalize(&(ctx[i]),&(sig_R[i]),&(sig_s[i]));
        if(k==-1){ 
            ext_printf("fianlize fail in %d\n",i);
        }else{
            ext_printf("(%d) fianlize signature successful!\n",i);
        }
    }

    /* check signature same with all signers */
    #if(BN_DEBUG==1)
    for(int i=1;i<SIGNERS_N;i++){
        if(nn_cmp(&(sig_s[i]),&(sig_s[0]))!=0){
            ext_printf("assert s fail in 0 with %d\n",i);
            return -1;
        }
        if(prj_pt_cmp(&(sig_R[i]),&(sig_R[0]))!=0){
            ext_printf("assert R fail in 0 with %d\n",i);
            return -1;
        }
    }
    #endif
    
    /* check aff_t */
    #if(BN_DEBUG==1)

    aff_pt convert[SIGNERS_N];
    for(int i=0;i<SIGNERS_N;i++){
        ext_printf("check %d aff_pt\n",i);
        prj_pt_to_aff(convert+i,sig_R+i);
        fp_print("x:",&(convert[i].x));
        fp_print("y:",&(convert[i].y));
    }

    #endif

    /* verify all signatures */
    for(int i=0;i<SIGNERS_N;i++){
        k = BN_verify(&ecparams,pubklist,SIGNERS_N,&(sig_R[i]),&(sig_s[i]),message,message_len);
        if(k==1){
            ext_printf("(%d) verify pass!\n",i);
        }else{
            ext_printf("(%d) verify refuse!\n",i);
        }
    }

    return 0;
}
