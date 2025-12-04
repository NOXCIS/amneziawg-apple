/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

#ifndef UDPTLSPIPE_H
#define UDPTLSPIPE_H

#include <stdint.h>

typedef void(*udptlspipe_logger_fn_t)(void *context, int level, const char *msg);

/**
 * Set the logger function for udptlspipe.
 *
 * @param context User context pointer passed to logger function.
 * @param logger_fn Logger function pointer
 */
void udptlspipeSetLogger(void *context, udptlspipe_logger_fn_t logger_fn);

/**
 * Start a udptlspipe client.
 *
 * @param destination Remote server address (e.g., "server.example.com:443")
 * @param password Password for authentication (can be NULL or empty)
 * @param tls_server_name TLS server name for SNI (can be NULL to use destination host)
 * @param secure If non-zero, enables TLS certificate verification
 * @param proxy Proxy URL (can be NULL or empty)
 * @param fingerprint_profile TLS fingerprint profile ("chrome", "firefox", "safari", "edge", "okhttp", "ios", "randomized")
 * @param listen_port Local port to listen on (0 for auto-assign)
 * @return Handle ID on success (> 0), or negative error code on failure
 */
int udptlspipeStart(const char *destination,
                    const char *password,
                    const char *tls_server_name,
                    int secure,
                    const char *proxy,
                    const char *fingerprint_profile,
                    int listen_port);

/**
 * Stop a running udptlspipe client.
 *
 * @param handle The handle ID returned by udptlspipeStart
 */
void udptlspipeStop(int handle);

/**
 * Get the local port for a running udptlspipe client.
 *
 * @param handle The handle ID returned by udptlspipeStart
 * @return Local port number, or 0 if handle is invalid
 */
int udptlspipeGetLocalPort(int handle);

/**
 * Get the version string of udptlspipe.
 *
 * @return Version string (caller should free this)
 */
char *udptlspipeVersion(void);

/**
 * Reset the cached randomized fingerprint pair.
 * This should be called when reconnecting to get a fresh fingerprint.
 * Only useful when using the "randomized" fingerprint profile.
 */
void udptlspipeResetFingerprint(void);

/**
 * Get the last error message, if any.
 *
 * @return Error message string (caller should free this), or NULL if no error
 */
char *udptlspipeGetLastError(void);

/**
 * Clear the last error message.
 */
void udptlspipeClearLastError(void);

#endif /* UDPTLSPIPE_H */

