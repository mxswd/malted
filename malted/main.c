//
//  main.c
//  malted
//
//  Created by Maxwell on 8/06/20.
//  Copyright © 2020 Maxwell Swadling. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#include <ctype.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

static const char magic[] = "Malted__";

// Pad to fit inside bluray sectors.
const int minHeaderSize = 2048; // bytes
// FIXME: implement header padding
// FIXME: implement larger buffer size?
// even without these improvements it can do 4gb in 1min 22s.
// OH NO. While encrypting is streaming, decryption IS NOT. So this won't work.

#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)

/* See OPT_FMT_xxx, above. */
/* On some platforms, it's important to distinguish between text and binary
 * files.  On some, there might even be specific file formats for different
 * contents.  The FORMAT_xxx macros are meant to express an intent with the
 * file being read or created.
 */
# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPubicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPubicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

# define APP_PASS_LEN    1024

static int set_hex(const char *in, unsigned char *out, int size);

struct doall_enc_ciphers {
    BIO *bio;
    int n;
};

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_LIST,
    OPT_E, OPT_IN, OPT_OUT, OPT_PASS, OPT_ENGINE, OPT_D, OPT_P, OPT_V,
    OPT_NOPAD, OPT_SALT, OPT_NOSALT, OPT_DEBUG, OPT_UPPER_P, OPT_UPPER_A,
    OPT_A, OPT_Z, OPT_BUFSIZE, OPT_K, OPT_KFILE, OPT_UPPER_K, OPT_NONE,
    OPT_UPPER_S, OPT_IV, OPT_MD, OPT_ITER, OPT_PBKDF2, OPT_CIPHER,
    OPT_R_ENUM
} OPTION_CHOICE;

//const OPTIONS enc_options[] = {
//    {"help", OPT_HELP, '-', "Display this summary"},
//    {"list", OPT_LIST, '-', "List ciphers"},
//    {"ciphers", OPT_LIST, '-', "Alias for -list"},
//    {"in", OPT_IN, '<', "Input file"},
//    {"out", OPT_OUT, '>', "Output file"},
//    {"pass", OPT_PASS, 's', "Passphrase source"},
//    {"e", OPT_E, '-', "Encrypt"},
//    {"d", OPT_D, '-', "Decrypt"},
//    {"p", OPT_P, '-', "Print the iv/key"},
//    {"P", OPT_UPPER_P, '-', "Print the iv/key and exit"},
//    {"v", OPT_V, '-', "Verbose output"},
//    {"nopad", OPT_NOPAD, '-', "Disable standard block padding"},
//    {"salt", OPT_SALT, '-', "Use salt in the KDF (default)"},
//    {"nosalt", OPT_NOSALT, '-', "Do not use salt in the KDF"},
//    {"debug", OPT_DEBUG, '-', "Print debug info"},
//    {"a", OPT_A, '-', "Base64 encode/decode, depending on encryption flag"},
//    {"base64", OPT_A, '-', "Same as option -a"},
//    {"A", OPT_UPPER_A, '-',
//     "Used with -[base64|a] to specify base64 buffer as a single line"},
//    {"bufsize", OPT_BUFSIZE, 's', "Buffer size"},
//    {"k", OPT_K, 's', "Passphrase"},
//    {"kfile", OPT_KFILE, '<', "Read passphrase from file"},
//    {"K", OPT_UPPER_K, 's', "Raw key, in hex"},
//    {"S", OPT_UPPER_S, 's', "Salt, in hex"},
//    {"iv", OPT_IV, 's', "IV in hex"},
//    {"md", OPT_MD, 's', "Use specified digest to create a key from the passphrase"},
//    {"iter", OPT_ITER, 'p', "Specify the iteration count and force use of PBKDF2"},
//    {"pbkdf2", OPT_PBKDF2, '-', "Use password-based key derivation function 2"},
//    {"none", OPT_NONE, '-', "Don't encrypt"},
//    {"", OPT_CIPHER, '-', "Any supported cipher"},
//    OPT_R_OPTIONS,
//#ifdef ZLIB
//    {"z", OPT_Z, '-', "Use zlib as the 'encryption'"},
//#endif
//#ifndef OPENSSL_NO_ENGINE
//    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
//#endif
//    {NULL}
//};

static BIO *bio_err;

void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    if (e != NULL)
        /* Free our "structural" reference. */
        ENGINE_free(e);
#endif
}

void* app_malloc(int sz, const char *what)
{
    void *vp = OPENSSL_malloc(sz);

    if (vp == NULL) {
        BIO_printf(bio_err, "Could not allocate %d bytes for %s\n",
                sz, what);
        ERR_print_errors(bio_err);
        exit(1);
    }
    return vp;
}

static int istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

BIO *dup_bio_in(int format)
{
    return BIO_new_fp(stdin,
                      BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
}

BIO *dup_bio_out(int format)
{
    BIO *b = BIO_new_fp(stdout,
                        BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
    void *prefix = NULL;

#ifdef OPENSSL_SYS_VMS
    if (istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif

    if (istext(format) && (prefix = getenv("HARNESS_OSSL_PREFIX")) != NULL) {
        perror("FIXME: not implemented");
        exit(1);
//        if (prefix_method == NULL)
//            prefix_method = apps_bf_prefix();
//        b = BIO_push(BIO_new(prefix_method), b);
//        BIO_ctrl(b, PREFIX_CTRL_SET_PREFIX, 0, prefix);
    }

    return b;
}

static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return istext(format) ? "a" : "ab";
    case 'r':
        return istext(format) ? "r" : "rb";
    case 'w':
        return istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}


static const char *modeverb(char mode)
{
    switch (mode) {
    case 'a':
        return "appending";
    case 'r':
        return "reading";
    case 'w':
        return "writing";
    }
    return "(doing something)";
}


static BIO *bio_open_default_(const char *filename, char mode, int format,
                              int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        BIO_printf(bio_err,
                   "Can't open %s, %s\n",
                   mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        BIO_printf(bio_err,
                   "Can't open %s for %s, %s\n",
                   filename, modeverb(mode), strerror(errno));
    }
    ERR_print_errors(bio_err);
    return NULL;
}

BIO *bio_open_default(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 0);
}


static char *app_get_pass(const char *arg, int keepbio)
{
    char *tmp, tpass[APP_PASS_LEN];
    static BIO *pwdbio = NULL;
    int i;

    if (strncmp(arg, "pass:", 5) == 0)
        return OPENSSL_strdup(arg + 5);
    if (strncmp(arg, "env:", 4) == 0) {
        tmp = getenv(arg + 4);
        if (tmp == NULL) {
            BIO_printf(bio_err, "Can't read environment variable %s\n", arg + 4);
            return NULL;
        }
        return OPENSSL_strdup(tmp);
    }
    if (!keepbio || pwdbio == NULL) {
        if (strncmp(arg, "file:", 5) == 0) {
            pwdbio = BIO_new_file(arg + 5, "r");
            if (pwdbio == NULL) {
                BIO_printf(bio_err, "Can't open file %s\n", arg + 5);
                return NULL;
            }
#if !defined(_WIN32)
            /*
             * Under _WIN32, which covers even Win64 and CE, file
             * descriptors referenced by BIO_s_fd are not inherited
             * by child process and therefore below is not an option.
             * It could have been an option if bss_fd.c was operating
             * on real Windows descriptors, such as those obtained
             * with CreateFile.
             */
        } else if (strncmp(arg, "fd:", 3) == 0) {
            BIO *btmp;
            i = atoi(arg + 3);
            if (i >= 0)
                pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
            if ((i < 0) || !pwdbio) {
                BIO_printf(bio_err, "Can't access file descriptor %s\n", arg + 3);
                return NULL;
            }
            /*
             * Can't do BIO_gets on an fd BIO so add a buffering BIO
             */
            btmp = BIO_new(BIO_f_buffer());
            pwdbio = BIO_push(btmp, pwdbio);
#endif
        } else if (strcmp(arg, "stdin") == 0) {
            pwdbio = dup_bio_in(FORMAT_TEXT);
            if (!pwdbio) {
                BIO_printf(bio_err, "Can't open BIO for stdin\n");
                return NULL;
            }
        } else {
            BIO_printf(bio_err, "Invalid password argument \"%s\"\n", arg);
            return NULL;
        }
    }
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    if (keepbio != 1) {
        BIO_free_all(pwdbio);
        pwdbio = NULL;
    }
    if (i <= 0) {
        BIO_printf(bio_err, "Error reading password from BIO\n");
        return NULL;
    }
    tmp = strchr(tpass, '\n');
    if (tmp != NULL)
        *tmp = 0;
    return OPENSSL_strdup(tpass);
}

int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2)
{
    int same;
    if (arg2 == NULL || arg1 == NULL || strcmp(arg1, arg2))
        same = 0;
    else
        same = 1;
    if (arg1 != NULL) {
        *pass1 = app_get_pass(arg1, same);
        if (*pass1 == NULL)
            return 0;
    } else if (pass1 != NULL) {
        *pass1 = NULL;
    }
    if (arg2 != NULL) {
        *pass2 = app_get_pass(arg2, same ? 2 : 0);
        if (*pass2 == NULL)
            return 0;
    } else if (pass2 != NULL) {
        *pass2 = NULL;
    }
    return 1;
}

void printUsage() {
    printf("malted (encrypt|decrypt) filename\n");
}

BIO *dup_bio_err(int format)
{
    BIO *b = BIO_new_fp(stderr,
                        BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
#ifdef OPENSSL_SYS_VMS
    if (istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif
    return b;
}

int main(int argc, char **argv)
{
    static char buf[128];
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
        NULL, *wbio = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL, *c;
    const EVP_MD *dgst = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL, *p;
    char *infile = NULL, *outfile = NULL;
    char *str = NULL, *passarg = NULL, *pass = NULL, *strbuf = NULL;
    char mbuf[sizeof(magic) - 1];
    OPTION_CHOICE o;
    int bsize = BSIZE, verbose = 0, debug = 0, olb64 = 0, nosalt = 0;
    int enc = 1, printkey = 0, i, k;
    int base64 = 0, informat = FORMAT_BINARY, outformat = FORMAT_BINARY;
    int ret = 1, inl, nopad = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *buff = NULL, salt[PKCS5_SALT_LEN];
    int pbkdf2 = 1;
    int iter = 1000000; // 1mil, 1 000 000.
    long n;
    
    bio_err = dup_bio_err(FORMAT_TEXT);

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if (cipher == NULL) {
        BIO_printf(bio_err, "missing aes-256-cbc cipher\n");
        goto end;
    }
    
    // simple opt parser
    if (argc == 3) {
        if (strncmp(argv[1], "encrypt", 7) == 0) {
            enc = 1;
            infile = argv[2];
            // FIXME: stat file to see if exists, if so abort.
            asprintf(&outfile,"%s.malted",infile);
        } else if (strncmp(argv[1], "decrypt", 7) == 0) {
            enc = 0;
            infile = argv[2];
            // FIXME: stat file to see if exists, if so abort.
            asprintf(&outfile,"%s.decrypted",infile);
        } else {
            printUsage();
            exit(0);
        }
    } else {

        printUsage();
        exit(0);
    }

    // debugging:
    printkey = 1;
    verbose = 1;
//    passarg = "password";
//    str = strdup("passwprd");

    
//    prog = opt_init(argc, argv, enc_options);
//    while ((o = opt_next()) != OPT_EOF) {
//        switch (o) {
//        case OPT_PASS:
//            passarg = opt_arg();
//            break;
//        case OPT_ENGINE:
//            e = setup_engine(opt_arg(), 0);
//            break;
//        case OPT_P:
//            printkey = 1;
//            break;
//        case OPT_V:
//            verbose = 1;
//            break;
//        case OPT_NOPAD:
//            nopad = 1;
//            break;
//        case OPT_SALT:
//            nosalt = 0;
//            break;
//        case OPT_NOSALT:
//            nosalt = 1;
//            break;
//        case OPT_DEBUG:
//            debug = 1;
//            break;
//        case OPT_UPPER_P:
//            printkey = 2;
//            break;
//        case OPT_UPPER_A:
//            olb64 = 1;
//            break;
//        case OPT_A:
//            base64 = 1;
//            break;
//        case OPT_BUFSIZE:
//            p = opt_arg();
//            i = (int)strlen(p) - 1;
//            k = i >= 1 && p[i] == 'k';
//            if (k)
//                p[i] = '\0';
//            if (!opt_long(opt_arg(), &n)
//                    || n < 0 || (k && n >= LONG_MAX / 1024))
//                goto opthelp;
//            if (k)
//                n *= 1024;
//            bsize = (int)n;
//            break;
//        case OPT_K:
//            str = opt_arg();
//            break;
//        case OPT_KFILE:
//            in = bio_open_default(opt_arg(), 'r', FORMAT_TEXT);
//            if (in == NULL)
//                goto opthelp;
//            i = BIO_gets(in, buf, sizeof(buf));
//            BIO_free(in);
//            in = NULL;
//            if (i <= 0) {
//                BIO_printf(bio_err,
//                           "%s Can't read key from %s\n", prog, opt_arg());
//                goto opthelp;
//            }
//            while (--i > 0 && (buf[i] == '\r' || buf[i] == '\n'))
//                buf[i] = '\0';
//            if (i <= 0) {
//                BIO_printf(bio_err, "%s: zero length password\n", prog);
//                goto opthelp;
//            }
//            str = buf;
//            break;
//        case OPT_UPPER_K:
//            hkey = opt_arg();
//            break;
//        case OPT_UPPER_S:
//            hsalt = opt_arg();
//            break;
//        case OPT_IV:
//            hiv = opt_arg();
//            break;
//        case OPT_MD:
//            if (!opt_md(opt_arg(), &dgst))
//                goto opthelp;
//            break;
//        case OPT_CIPHER:
//            if (!opt_cipher(opt_unknown(), &c))
//                goto opthelp;
//            cipher = c;
//            break;
//        case OPT_NONE:
//            cipher = NULL;
//            break;
//        case OPT_R_CASES:
//            if (!opt_rand(o))
//                goto end;
//            break;
//        }
//    }

    if (cipher && EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        BIO_printf(bio_err, "AEAD ciphers not supported\n");
        goto end;
    }

    if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)) {
        BIO_printf(bio_err, "XTS ciphers not supported\n");
        goto end;
    }

    if (dgst == NULL)
        dgst = EVP_sha256();

    if (iter == 0)
        iter = 1;

    /* It must be large enough for a base64 encoded line */
    if (base64 && bsize < 80)
        bsize = 80;
    if (verbose)
        BIO_printf(bio_err, "bufsize=%d\n", bsize);

        if (base64) {
            if (enc)
                outformat = FORMAT_BASE64;
            else
                informat = FORMAT_BASE64;
        }

    strbuf = app_malloc(SIZE, "strbuf");
    buff = app_malloc(EVP_ENCODE_LENGTH(bsize), "evp buffer");

    if (infile == NULL) {
        in = dup_bio_in(informat);
    } else {
        in = bio_open_default(infile, 'r', informat);
    }
    if (in == NULL)
        goto end;

    if (str == NULL && passarg != NULL) {
        if (!app_passwd(passarg, NULL, &pass, NULL)) {
            BIO_printf(bio_err, "Error getting password\n");
            goto end;
        }
        str = pass;
    }

    if ((str == NULL) && (cipher != NULL) && (hkey == NULL)) {
        if (1) {
#ifndef OPENSSL_NO_UI_CONSOLE
            for (;;) {
                char prompt[200];

                BIO_snprintf(prompt, sizeof(prompt), "enter %s %s password:",
                        OBJ_nid2ln(EVP_CIPHER_nid(cipher)),
                        (enc) ? "encryption" : "decryption");
                strbuf[0] = '\0';
                i = EVP_read_pw_string((char *)strbuf, SIZE, prompt, enc);
                if (i == 0) {
                    if (strbuf[0] == '\0') {
                        ret = 1;
                        goto end;
                    }
                    str = strbuf;
                    break;
                }
                if (i < 0) {
                    BIO_printf(bio_err, "bad password read\n");
                    goto end;
                }
            }
        } else {
#endif
            BIO_printf(bio_err, "password required\n");
            goto end;
        }
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

//    if (debug) {
//        BIO_set_callback(in, BIO_debug_callback);
//        BIO_set_callback(out, BIO_debug_callback);
//        BIO_set_callback_arg(in, (char *)bio_err);
//        BIO_set_callback_arg(out, (char *)bio_err);
//    }

    rbio = in;
    wbio = out;

    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
//        if (debug) {
//            BIO_set_callback(b64, BIO_debug_callback);
//            BIO_set_callback_arg(b64, (char *)bio_err);
//        }
        if (olb64)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    if (cipher != NULL) {
        /*
         * Note that str is NULL if a key was passed on the command line, so
         * we get no salt in that case. Is this a bug?
         */
        if (str != NULL) {
            /*
             * Salt handling: if encrypting generate a salt and write to
             * output BIO. If decrypting read salt from input BIO.
             */
            unsigned char *sptr;
            size_t str_len = strlen(str);

            if (nosalt) {
                sptr = NULL;
            } else {
                if (enc) {
                    if (hsalt) {
                        if (!set_hex(hsalt, salt, sizeof(salt))) {
                            BIO_printf(bio_err, "invalid hex salt value\n");
                            goto end;
                        }
                    } else if (RAND_bytes(salt, sizeof(salt)) <= 0) {
                        goto end;
                    }
                    /*
                     * If -P option then don't bother writing
                     */
                    if ((printkey != 2)
                        && (BIO_write(wbio, magic,
                                      sizeof(magic) - 1) != sizeof(magic) - 1
                            || BIO_write(wbio,
                                         (char *)salt,
                                         sizeof(salt)) != sizeof(salt))) {
                        BIO_printf(bio_err, "error writing output file\n");
                        goto end;
                    }
                } else if (BIO_read(rbio, mbuf, sizeof(mbuf)) != sizeof(mbuf)
                           || BIO_read(rbio,
                                       (unsigned char *)salt,
                                       sizeof(salt)) != sizeof(salt)) {
                    BIO_printf(bio_err, "error reading input file\n");
                    goto end;
                } else if (memcmp(mbuf, magic, sizeof(magic) - 1)) {
                    BIO_printf(bio_err, "bad magic number\n");
                    goto end;
                }
                sptr = salt;
            }

            if (pbkdf2 == 1) {
                /*
                * derive key and default iv
                * concatenated into a temporary buffer
                */
                unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
                int iklen = EVP_CIPHER_key_length(cipher);
                int ivlen = EVP_CIPHER_iv_length(cipher);
                /* not needed if HASH_UPDATE() is fixed : */
                int islen = (sptr != NULL ? sizeof(salt) : 0);
                if (!PKCS5_PBKDF2_HMAC(str, str_len, sptr, islen,
                                       iter, dgst, iklen+ivlen, tmpkeyiv)) {
                    BIO_printf(bio_err, "PKCS5_PBKDF2_HMAC failed\n");
                    goto end;
                }
                /* split and move data back to global buffer */
                memcpy(key, tmpkeyiv, iklen);
                memcpy(iv, tmpkeyiv+iklen, ivlen);
            } else {
                BIO_printf(bio_err, "*** WARNING : "
                                    "deprecated key derivation used.\n"
                                    "Using -iter or -pbkdf2 would be better.\n");
                if (!EVP_BytesToKey(cipher, dgst, sptr,
                                    (unsigned char *)str, str_len,
                                    1, key, iv)) {
                    BIO_printf(bio_err, "EVP_BytesToKey failed\n");
                    goto end;
                }
            }
            /*
             * zero the complete buffer or the string passed from the command
             * line.
             */
            if (str == strbuf)
                OPENSSL_cleanse(str, SIZE);
            else
                OPENSSL_cleanse(str, str_len);
        }
        if (hiv != NULL) {
            int siz = EVP_CIPHER_iv_length(cipher);
            if (siz == 0) {
                BIO_printf(bio_err, "warning: iv not used by this cipher\n");
            } else if (!set_hex(hiv, iv, siz)) {
                BIO_printf(bio_err, "invalid hex iv value\n");
                goto end;
            }
        }
        if ((hiv == NULL) && (str == NULL)
            && EVP_CIPHER_iv_length(cipher) != 0) {
            /*
             * No IV was explicitly set and no IV was generated.
             * Hence the IV is undefined, making correct decryption impossible.
             */
            BIO_printf(bio_err, "iv undefined\n");
            goto end;
        }
        if (hkey != NULL) {
            if (!set_hex(hkey, key, EVP_CIPHER_key_length(cipher))) {
                BIO_printf(bio_err, "invalid hex key value\n");
                goto end;
            }
            /* wiping secret data as we no longer need it */
            OPENSSL_cleanse(hkey, strlen(hkey));
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &ctx);

        // FIXME: what is this line for? Just remove it?
        if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

//        if (nopad)
        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

//        if (debug) {
//            BIO_set_callback(benc, BIO_debug_callback);
//            BIO_set_callback_arg(benc, (char *)bio_err);
//        }

        if (printkey) {
            if (!nosalt) {
                printf("salt=");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("%02X", salt[i]);
                printf("\n");
            }
            if (EVP_CIPHER_key_length(cipher) > 0) {
                printf("key=");
                for (i = 0; i < EVP_CIPHER_key_length(cipher); i++)
                    printf("%02X", key[i]);
                printf("\n");
            }
            if (EVP_CIPHER_iv_length(cipher) > 0) {
                printf("iv =");
                for (i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
                    printf("%02X", iv[i]);
                printf("\n");
            }
            if (printkey == 2) {
                ret = 0;
                goto end;
            }
        }
    }

    /* Only encrypt/decrypt as we write the file */
    if (benc != NULL)
        wbio = BIO_push(benc, wbio);

    while (BIO_pending(rbio) || !BIO_eof(rbio)) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl) {
            BIO_printf(bio_err, "error writing output file\n");
            goto end;
        }
    }
    
    if (!BIO_flush(wbio)) {
        BIO_printf(bio_err, "bad decrypt\n");
        goto end;
    }

    ret = 0;
    if (verbose) {
        BIO_printf(bio_err, "bytes read   : %8ju\n", BIO_number_read(in));
        BIO_printf(bio_err, "bytes written: %8ju\n", BIO_number_written(out));
    }
 end:
    ERR_print_errors(bio_err);
    OPENSSL_free(strbuf);
    OPENSSL_free(buff);
    BIO_free(in);
    BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);
#ifdef ZLIB
    BIO_free(bzl);
#endif
    release_engine(e);
    OPENSSL_free(pass);
    return ret;
}

static int set_hex(const char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    i = size * 2;
    n = strlen(in);
    if (n > i) {
        BIO_printf(bio_err, "hex string is too long, ignoring excess\n");
        n = i; /* ignore exceeding part */
    } else if (n < i) {
        BIO_printf(bio_err, "hex string is too short, padding with zero bytes to length\n");
    }

    memset(out, 0, size);
    for (i = 0; i < n; i++) {
        j = (unsigned char)*in++;
        if (!isxdigit(j)) {
            BIO_printf(bio_err, "non-hex digit\n");
            return 0;
        }
        j = (unsigned char)OPENSSL_hexchar2int(j);
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return 1;
}
