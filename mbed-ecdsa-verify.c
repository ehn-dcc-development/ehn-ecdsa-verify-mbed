/* Copyright 2021, Ministry of Public Health, Welfare and Sports of the Netherlands.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"

#include <string.h>

#define EXITONERR(x) { if (0 != (x)) { fprintf(stderr,"Error on line %d, exiting\n", __LINE__); };}

int main( int argc, char *argv[] )
{ 
    int ret = 1;

    mbedtls_ecdsa_context ctx_verify;
    mbedtls_ecdsa_init( &ctx_verify ); /*Initialize the ecdsa verify structure*/

    if (argc != 5) {
	fprintf(stderr,"Args: %s b64X b64Y b64SIG payloadstring\n", argv[0]);
        goto exit;
    }
    unsigned char * message = (unsigned char *) argv[4];
    size_t message_len = strlen(argv[4]);

    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = MBEDTLS_ECDSA_MAX_LEN;

    EXITONERR(mbedtls_base64_decode (sig,sizeof(sig),&sig_len, (const unsigned char *) argv[3],strlen(argv[3])));

    unsigned char hash[32];
    EXITONERR(mbedtls_sha256_ret( message, message_len, hash, 0 ));

    EXITONERR(mbedtls_ecp_group_load( &ctx_verify.grp, MBEDTLS_ECP_DP_SECP256R1));

    // load the public key
    ///
    mbedtls_ecp_point pubkey;
    mbedtls_ecp_point_init(&pubkey);
    EXITONERR(mbedtls_ecp_point_read_string (&pubkey, 16, argv[1], argv[2]));
    EXITONERR(mbedtls_ecp_copy( &ctx_verify.Q, &pubkey));

    /*
     * Verify signature
     */
    printf( "Verifying signature (%zu, %zu)...",sig_len, sizeof(hash));
    fflush( stdout );

    EXITONERR(mbedtls_ecdsa_read_signature( &ctx_verify, hash, sizeof( hash ), sig, sig_len));
    printf("signature ok\n" );

exit:
    mbedtls_ecdsa_free( &ctx_verify );
    return( ret );
}
