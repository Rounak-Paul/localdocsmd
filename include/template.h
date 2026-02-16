#ifndef TEMPLATE_H
#define TEMPLATE_H

#include "localdocsmd.h"
#include <stdarg.h>

// Template variable
typedef struct {
    char *name;
    char *value;
} template_var_t;

// Template context
typedef struct {
    template_var_t *vars;
    int var_count;
    int var_capacity;
} template_ctx_t;

/**
 * Create template context
 * @return New context (caller frees)
 */
template_ctx_t *template_create_context(void);

/**
 * Free template context
 * @param ctx Context to free
 */
void template_free_context(template_ctx_t *ctx);

/**
 * Set variable in context
 * @param ctx Context
 * @param name Variable name
 * @param value Variable value
 */
void template_set(template_ctx_t *ctx, const char *name, const char *value);

/**
 * Set integer variable
 * @param ctx Context
 * @param name Variable name
 * @param value Integer value
 */
void template_set_int(template_ctx_t *ctx, const char *name, int value);

/**
 * Set boolean variable
 * @param ctx Context
 * @param name Variable name
 * @param value Boolean value
 */
void template_set_bool(template_ctx_t *ctx, const char *name, bool value);

/**
 * Load and render template
 * @param web_root Web root path
 * @param template_name Template name (e.g., "login.html")
 * @param ctx Template context
 * @param output_out Output HTML (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t template_render(const char *web_root, const char *template_name,
                             template_ctx_t *ctx, char **output_out);

/**
 * Render template with layout
 * @param web_root Web root path
 * @param template_name Template name
 * @param ctx Template context
 * @param output_out Output HTML (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t template_render_with_layout(const char *web_root, const char *template_name,
                                         template_ctx_t *ctx, char **output_out);

/**
 * Load template file
 * @param path Template file path
 * @param content_out Output content (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t template_load_file(const char *path, char **content_out);

/**
 * HTML escape string
 * @param str Input string
 * @param escaped_out Output escaped string (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t template_html_escape(const char *str, char **escaped_out);

/**
 * JSON escape string
 * @param str Input string
 * @param escaped_out Output escaped string (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t template_json_escape(const char *str, char **escaped_out);

#endif // TEMPLATE_H
