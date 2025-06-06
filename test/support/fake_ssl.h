
#ifndef _HE_FAKE_SSL
#define _HE_FAKE_SSL



int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);
int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx);
long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl);
int wolfSSL_Rehandshake(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SecureResume(WOLFSSL* ssl);
int wolfSSL_dtls13_allow_ch_frag(WOLFSSL *ssl, int enabled);
int  wolfSSL_dtls_set_mtu(WOLFSSL* ssl, unsigned short mtu);
WOLFSSL_API int  wolfSSL_update_keys(WOLFSSL* ssl);

#endif
