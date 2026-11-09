#ifndef INVISI_WALLET_H
#define INVISI_WALLET_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Methods: wallet.public, wallet.detect, wallet.decryptNote,
   wallet.decryptCredit and wallet.authorize.
   Requests and results are JSON arrays (up to 1024 members / 16 MiB).
   Inputs are borrowed. Free returned JSON with invisi_wallet_free. */
char *invisi_wallet_execute_batch(const uint8_t *key, size_t key_len,
                                 const uint8_t *request, size_t request_len);
void invisi_wallet_free(char *result);
#ifdef __cplusplus
}
#endif
#endif
