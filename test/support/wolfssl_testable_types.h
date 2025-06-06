#ifndef WOLFSSL_TESTABLE_TYPES
#define WOLFSSL_TESTABLE_TYPES

//        #define WOLFSSL_API   __attribute__ ((visibility("default")))
//        #define WOLFSSL_LOCAL __attribute__ ((visibility("hidden")))

#define WOLFSSL_API
#define WOLFSSL_LOCAL

typedef struct WOLFSSL {
  int id;
} WOLFSSL;

typedef struct WOLFSSL_CTX {
  int id;
} WOLFSSL_CTX;

struct WOLFSSL_CERT_MANAGER {
  int id;
};

struct WOLFSSL_X509 {
  int id;
};

struct WOLFSSL_X509_CRL {
  int id;
};

struct WOLFSSL_X509_NAME {
  int id;
};

struct WOLFSSL_X509_NAME_ENTRY {
  int id;
};

struct WOLFSSL_X509_CHAIN {
  int id;
};

struct WOLFSSL_X509_VERIFY_PARAM {
  int id;
};

struct WOLFSSL_CRL {
  int id;
};

struct WOLFSSL_STACK {
  int id;
};

struct WOLFSSL_CIPHER {
  int id;
};

struct WOLFSSL_METHOD {
  int id;
};

struct WOLFSSL_CHAIN {
  int id;
};

struct WOLFSSL_SESSION {
  int id;
};

struct WOLFSSL_DH {
  int id;
};

struct WOLFSSL_RSA {
  int id;
};

struct WC_PKCS12 {
  int id;
};

struct WOLFSSL_EVP_MD_CTX {
  int id;
};

struct WOLFSSL_X509_EXTENSION {
  int id;
};

struct WOLFSSL_BIO {
  int id;
};

typedef unsigned int (*wc_psk_client_callback)(WOLFSSL* ssl, const char*, char*,
                            unsigned int, unsigned char*, unsigned int);
typedef unsigned int (*wc_psk_server_callback)(WOLFSSL* ssl, const char*,
		  unsigned char*, unsigned int);
#endif
