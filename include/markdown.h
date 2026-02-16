#ifndef MARKDOWN_H
#define MARKDOWN_H

#include "localdocsmd.h"

/**
 * Render markdown to HTML
 * @param markdown Markdown content
 * @param html_out Output HTML (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t markdown_render(const char *markdown, char **html_out);

/**
 * Render markdown to HTML with full page wrapper
 * @param markdown Markdown content
 * @param title Page title
 * @param html_out Output HTML (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t markdown_render_page(const char *markdown, const char *title, char **html_out);

/**
 * Extract title from markdown (first H1)
 * @param markdown Markdown content
 * @param title_out Output title (caller frees)
 * @return LDMD_OK or LDMD_ERROR_NOT_FOUND
 */
ldmd_error_t markdown_extract_title(const char *markdown, char **title_out);

/**
 * Sanitize markdown (remove dangerous content)
 * @param markdown Input markdown
 * @param sanitized_out Output sanitized markdown (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t markdown_sanitize(const char *markdown, char **sanitized_out);

#endif // MARKDOWN_H
