#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iostream>
#include <cstring>

using std::cout;
using std::cin;
using std::endl;
using std::cerr;

void fastModExp(BIGNUM * ,BIGNUM *, BIGNUM *, BIGNUM *);
bool isPrime(BIGNUM *, int);
int GCD(BIGNUM *, BIGNUM *);
BIGNUM *exEuclidAlg(BIGNUM *, BIGNUM *);
void exEuclidDriver(BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *);

int main(int argc, char **argv){
    BIGNUM *one = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *phiN = BN_new();
    BIGNUM *bnMsg = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *d;
    BN_CTX *ctx = BN_CTX_new();

    unsigned char msg[4096];
    int len;
    char *nStr, *dStr, *pStr, *qStr, *phiNstr, quit = 0, *resStr;
    bool fast = false;

    if(argc != 2){
        cerr << "usage: " << argv[0] << " -fast|rand\n";
        exit(1);
    }

    if(strcmp(argv[1] + 1, "fast") == 0) fast = true;

    BN_one(one);
    BN_dec2bn(&e, "65537");

    do{
        if(fast) BN_generate_prime_ex(p, 1024, true, NULL, NULL, NULL);
        else     BN_rand(p, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        while(!isPrime(p, 10)){
            if(fast) BN_generate_prime_ex(p, 1024, true, NULL, NULL, NULL);
            else     BN_rand(p, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        }

        if(fast) BN_generate_prime_ex(q, 1024, true, NULL, NULL, NULL);
        else     BN_rand(q, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        while(!isPrime(q, 10)){
            if(fast) BN_generate_prime_ex(q, 1024, true, NULL, NULL, NULL);
            else     BN_rand(q, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        }

        pStr = BN_bn2dec(p);
        qStr = BN_bn2dec(q);
        cout << "p: " << pStr << endl << endl;
        cout << "q: " << qStr << endl << endl;
        OPENSSL_free(pStr);
        OPENSSL_free(qStr);

        BN_mul(n, p, q, ctx);
        BN_sub(p, p, one);
        BN_sub(q, q, one);
        BN_mul(phiN, p, q, ctx);
    }
    while(GCD(BN_dup(phiN), BN_dup(e)) != 1);

    d = exEuclidAlg(phiN, e);
    
    nStr = BN_bn2dec(n);
    dStr = BN_bn2dec(d);  
    phiNstr = BN_bn2dec(phiN);

    cout << "n: " << nStr << endl << endl;
    cout << "phiNstr: " << phiNstr << endl << endl;
    cout << "d: " << dStr << endl << endl;
    OPENSSL_free(nStr);
    OPENSSL_free(dStr);
    OPENSSL_free(phiNstr);

    while(quit != 'n' && quit != 'N'){
        cout << "Enter message: ";
        cin >>(char *) msg;
        len = strlen((char *) msg);

        cout << "Encrypt of Decrypt (e|d): ";
        cin >> quit;
        cout << endl;
        if(quit == 'e' || quit == 'E'){
            BN_bin2bn(msg, len, bnMsg);
            fastModExp(result, bnMsg, e, n);
            resStr = BN_bn2dec(result);
            cout << "Encrypted: " << resStr << endl << endl;
            OPENSSL_free(resStr);
        }
        else{
            BN_dec2bn(&bnMsg, (char *) msg);
            fastModExp(result, bnMsg, d, n);
            len = BN_num_bytes(result);
            BN_bn2bin(result, msg);
            msg[len] = '\0';
            cout << "Decrypted: " << (char *) msg << endl;
        }
        cout << "Continue (y|n): ";
        cin >> quit;
    }
    

    BN_free(one);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(phiN);
    BN_free(bnMsg);
    BN_free(result);
    BN_free(d);
    BN_CTX_free(ctx);
}

void fastModExp(BIGNUM *product, BIGNUM *b, BIGNUM *e, BIGNUM *n){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *mod = BN_new();
    BN_one(product);
    while(!BN_is_zero(e)){
        if(BN_is_odd(e)) {
            BN_mul(product, product, b, ctx);
            BN_mod(mod, product, n, ctx);
            BN_copy(product, mod);
        }
        BN_sqr(b, b, ctx);
        BN_mod(mod, b, n, ctx);
        BN_copy(b, mod);
        BN_rshift1(e, e);
    }
    BN_CTX_free(ctx);
    BN_free(mod);
}

bool isPrime(BIGNUM *n, int k){
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *nMinusTwo = BN_new();
    BIGNUM *nMinusOne = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *x2 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int s = 0;

    BN_one(one);
    BN_add(two, one, one);
    
    BN_sub(nMinusOne, n, one);
    BN_sub(nMinusTwo, n, two);

    BN_sub(d, n, one);

    while(!BN_is_odd(d)){ BN_div(d, NULL, d, two, ctx); s++;}
    
    
    for(int i = 0; i < k; i++){
        BN_rand_range(a, nMinusTwo);
        BN_add(a, a, one);
        fastModExp(x, a, d, n);
        if(BN_cmp(x, one) == 0|| BN_cmp(x, nMinusOne) == 0) continue;
        for(int j = 0; j < s; j++){
            BN_sqr(x, x, ctx);
            BN_mod(x, x, n, ctx);
            if(BN_cmp(x, nMinusOne) == 0) break;
        }
        if(BN_cmp(x, nMinusOne) == 0) continue;
        BN_free(d);
        BN_free(one);
        BN_free(two);
        BN_free(a);
        BN_free(nMinusTwo);
        BN_free(nMinusOne);
        BN_free(x);
        BN_free(x2);
        BN_CTX_free(ctx);
        return false;
    }
    BN_free(d);
    BN_free(one);
    BN_free(two);
    BN_free(a);
    BN_free(nMinusTwo);
    BN_free(nMinusOne);
    BN_free(x);
    BN_free(x2);
    BN_CTX_free(ctx);

    return true;
}

int GCD(BIGNUM *a, BIGNUM *b){
    char *str;
    int gcd;
    BN_CTX *ctx = BN_CTX_new();
    if(BN_is_zero(b)){ 
        str = BN_bn2dec(a);
        gcd = atoi(str);
        BN_free(a);
        BN_free(b);
        OPENSSL_free(str);
        BN_CTX_free(ctx);
        return gcd;
    }
    else{
        BN_mod(a, a, b, ctx);
        BN_CTX_free(ctx);
        return GCD(b, a);
    }
}

BIGNUM *exEuclidAlg(BIGNUM *a, BIGNUM *b){
    BIGNUM *s = BN_new();
    BIGNUM *t = BN_new();
    BIGNUM *tempA = BN_dup(a);
    BIGNUM *tempB = BN_dup(b);

    exEuclidDriver(tempA, tempB, s, t);
    BN_zero(s);
    if(BN_cmp(t, s) == -1){
        BN_add(t, t, a);
    }
    BN_free(s);
    BN_free(tempA);
    BN_free(tempB);
    return t;
}

void exEuclidDriver(BIGNUM *a, BIGNUM *b, BIGNUM *s, BIGNUM *t){
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if(BN_is_zero(a)){
        BN_zero(s);
        BN_one(t);
        BN_free(temp1);
        BN_free(temp2);
        BN_CTX_free(ctx);
        return;
    }
    BN_mod(temp1, b, a, ctx);
    exEuclidDriver(temp1, a, s, t);

    BN_copy(temp2, s);
    BN_div(temp1, NULL, b, a, ctx);
    BN_mul(temp1, temp1, s, ctx);
    BN_sub(s, t, temp1);
    BN_copy(t, temp2);
    BN_free(temp1);
    BN_free(temp2);
    BN_CTX_free(ctx);
    return;
}