#ifndef PRESIGN_H
#define PRESIGN_H

#include "localdocsmd.h"

/**
 * Presigned URL tokens for temporary, authenticated-free document access.
 *
 * Tokens are stored in an in-memory array protected by a mutex.
 * No DB schema change is required.  Tokens are invalidated on server restart,
 * which is acceptable (and desirable from a security standpoint).
 */

#define PRESIGN_MAX_ENTRIES  2048
#define PRESIGN_EXPIRE_SECS  86400   /* 24 hours */

/**
 * Initialise the presign store (call once at startup).
 */
void presign_init(void);

/**
 * Create a new presigned token for @doc_uuid / @user_id.
 *
 * @param doc_uuid    UUID of the document.
 * @param user_id     ID of the user who requested the token.
 * @param token_out   Buffer of at least LDMD_TOKEN_LENGTH bytes; receives the
 *                    random hex token.
 * @return LDMD_OK on success, LDMD_ERROR if the store is full.
 */
ldmd_error_t presign_create(const char *doc_uuid, int64_t user_id,
                            char *token_out);

/**
 * Validate a presigned token and retrieve the associated document UUID.
 *
 * @param token        Token string to validate.
 * @param doc_uuid_out Buffer of at least LDMD_UUID_LENGTH bytes; receives the
 *                     document UUID.  May be NULL.
 * @param user_id_out  Receives the ID of the user who created the token.  May
 *                     be NULL if the caller does not need it.
 * @return LDMD_OK if the token is valid and not expired, otherwise
 *         LDMD_ERROR_UNAUTHORIZED.
 */
ldmd_error_t presign_validate(const char *token, char *doc_uuid_out,
                              int64_t *user_id_out);

#endif /* PRESIGN_H */
