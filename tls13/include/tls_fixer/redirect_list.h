#ifndef TLS_FIXER_REDIRECT_LIST_H
#define TLS_FIXER_REDIRECT_LIST_H

#include "tls_fixer/host_map.h"
#include "tls_fixer/redirects.h"

/* Reading the host redirect list one line at a time, in pieces of TLS_FIXER_REDIRECTS_CHUNK bytes,
 * up to 64 KiB; shared by the HTTP provider and tls_fixer_psn. */

/* Longer than any valid pair (two 253-character names and a space between them) */
#define TLS_FIXER_REDIRECT_LIST_LINE_LIMIT 512u
/* The working memory the caller lends the reader: one piece and one line */
#define TLS_FIXER_REDIRECT_LIST_WORK_SIZE (TLS_FIXER_REDIRECTS_CHUNK + TLS_FIXER_REDIRECT_LIST_LINE_LIMIT)

#ifdef __cplusplus
extern "C" {
#endif

/* Reads up to size bytes of the list from offset, as tls_fixer_redirects_read does */
typedef int (*TlsFixerRedirectListRead)(unsigned int offset, void *buffer, unsigned int size);
/* Called for each valid pair, which points into the reader's line buffer and must be copied;
 * returns nonzero to stop reading (the list is full, or the caller failed) */
typedef int (*TlsFixerRedirectListKeep)(void *context, const TlsFixerHostRule *rule);

/* Reads the whole list, or until keep asks to stop; work holds TLS_FIXER_REDIRECT_LIST_WORK_SIZE
 * bytes. A line longer than the line limit is kept only when the cut fell inside a comment
 * Returns 0, or the read error that ended the list early (the pairs before it were passed on) */
int tls_fixer_redirect_list_read(TlsFixerRedirectListRead read, char *work, TlsFixerRedirectListKeep keep,
    void *context);

#ifdef __cplusplus
}
#endif

#endif
