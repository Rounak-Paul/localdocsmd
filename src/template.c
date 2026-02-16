#include "template.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

template_ctx_t *template_create_context(void) {
    template_ctx_t *ctx = calloc(1, sizeof(template_ctx_t));
    if (!ctx) return NULL;
    
    ctx->var_capacity = 32;
    ctx->vars = calloc(ctx->var_capacity, sizeof(template_var_t));
    if (!ctx->vars) {
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void template_free_context(template_ctx_t *ctx) {
    if (ctx) {
        for (int i = 0; i < ctx->var_count; i++) {
            free(ctx->vars[i].name);
            free(ctx->vars[i].value);
        }
        free(ctx->vars);
        free(ctx);
    }
}

void template_set(template_ctx_t *ctx, const char *name, const char *value) {
    if (!ctx || !name) return;
    
    // Check if already exists
    for (int i = 0; i < ctx->var_count; i++) {
        if (strcmp(ctx->vars[i].name, name) == 0) {
            free(ctx->vars[i].value);
            ctx->vars[i].value = value ? utils_strdup(value) : utils_strdup("");
            return;
        }
    }
    
    // Add new variable
    if (ctx->var_count >= ctx->var_capacity) {
        ctx->var_capacity *= 2;
        ctx->vars = realloc(ctx->vars, ctx->var_capacity * sizeof(template_var_t));
    }
    
    ctx->vars[ctx->var_count].name = utils_strdup(name);
    ctx->vars[ctx->var_count].value = value ? utils_strdup(value) : utils_strdup("");
    ctx->var_count++;
}

void template_set_int(template_ctx_t *ctx, const char *name, int value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", value);
    template_set(ctx, name, buf);
}

void template_set_bool(template_ctx_t *ctx, const char *name, bool value) {
    template_set(ctx, name, value ? "true" : "");
}

static const char *template_get(template_ctx_t *ctx, const char *name) {
    if (!ctx || !name) return "";
    
    for (int i = 0; i < ctx->var_count; i++) {
        if (strcmp(ctx->vars[i].name, name) == 0) {
            return ctx->vars[i].value ? ctx->vars[i].value : "";
        }
    }
    
    return "";
}

// Simple template engine supporting:
// {{variable}} - variable substitution
// {{#if variable}}...{{/if}} - conditional
// {{#unless variable}}...{{/unless}} - negative conditional
// {{#each items}}...{{/each}} - iteration (simplified - just shows count)
static ldmd_error_t template_process(const char *tpl, template_ctx_t *ctx, char **output) {
    size_t capacity = strlen(tpl) * 2 + 1024;
    char *result = malloc(capacity);
    if (!result) return LDMD_ERROR_MEMORY;
    
    size_t pos = 0;
    const char *p = tpl;
    
    while (*p) {
        // Check for template tag
        if (*p == '{' && *(p+1) == '{') {
            p += 2;
            
            // Find closing }}
            const char *end = strstr(p, "}}");
            if (!end) {
                // No closing tag, copy literally
                result[pos++] = '{';
                result[pos++] = '{';
                continue;
            }
            
            // Extract tag content
            size_t tag_len = end - p;
            char *tag = malloc(tag_len + 1);
            strncpy(tag, p, tag_len);
            tag[tag_len] = '\0';
            
            char *trimmed = utils_trim(tag);
            
            // Handle different tag types
            if (trimmed[0] == '#') {
                // Control structure
                if (strncmp(trimmed, "#if ", 4) == 0) {
                    const char *var_name = utils_trim(trimmed + 4);
                    const char *value = template_get(ctx, var_name);
                    bool condition = (value && strlen(value) > 0 && strcmp(value, "false") != 0);
                    
                    // Find {{/if}}
                    char closing[64];
                    snprintf(closing, sizeof(closing), "{{/if}}");
                    const char *endif = strstr(end + 2, closing);
                    
                    if (endif) {
                        if (condition) {
                            // Process content between
                            size_t content_len = endif - (end + 2);
                            char *content = malloc(content_len + 1);
                            strncpy(content, end + 2, content_len);
                            content[content_len] = '\0';
                            
                            char *processed = NULL;
                            template_process(content, ctx, &processed);
                            free(content);
                            
                            if (processed) {
                                size_t proc_len = strlen(processed);
                                if (pos + proc_len >= capacity) {
                                    capacity = (pos + proc_len) * 2;
                                    result = realloc(result, capacity);
                                }
                                strcpy(result + pos, processed);
                                pos += proc_len;
                                free(processed);
                            }
                        }
                        p = endif + strlen(closing);
                    } else {
                        p = end + 2;
                    }
                } else if (strncmp(trimmed, "#unless ", 8) == 0) {
                    const char *var_name = utils_trim(trimmed + 8);
                    const char *value = template_get(ctx, var_name);
                    bool condition = !(value && strlen(value) > 0 && strcmp(value, "false") != 0);
                    
                    char closing[64];
                    snprintf(closing, sizeof(closing), "{{/unless}}");
                    const char *endunless = strstr(end + 2, closing);
                    
                    if (endunless) {
                        if (condition) {
                            size_t content_len = endunless - (end + 2);
                            char *content = malloc(content_len + 1);
                            strncpy(content, end + 2, content_len);
                            content[content_len] = '\0';
                            
                            char *processed = NULL;
                            template_process(content, ctx, &processed);
                            free(content);
                            
                            if (processed) {
                                size_t proc_len = strlen(processed);
                                if (pos + proc_len >= capacity) {
                                    capacity = (pos + proc_len) * 2;
                                    result = realloc(result, capacity);
                                }
                                strcpy(result + pos, processed);
                                pos += proc_len;
                                free(processed);
                            }
                        }
                        p = endunless + strlen(closing);
                    } else {
                        p = end + 2;
                    }
                } else {
                    // Unknown control structure, skip
                    p = end + 2;
                }
            } else if (trimmed[0] == '/') {
                // Closing tag, skip (handled by opening)
                p = end + 2;
            } else {
                // Variable substitution
                const char *value = template_get(ctx, trimmed);
                size_t val_len = strlen(value);
                
                if (pos + val_len >= capacity) {
                    capacity = (pos + val_len) * 2;
                    result = realloc(result, capacity);
                }
                
                strcpy(result + pos, value);
                pos += val_len;
                p = end + 2;
            }
            
            free(tag);
        } else {
            // Regular character
            if (pos + 1 >= capacity) {
                capacity *= 2;
                result = realloc(result, capacity);
            }
            result[pos++] = *p++;
        }
    }
    
    result[pos] = '\0';
    *output = result;
    return LDMD_OK;
}

ldmd_error_t template_load_file(const char *path, char **content_out) {
    return utils_read_file(path, content_out);
}

ldmd_error_t template_render(const char *web_root, const char *template_name,
                             template_ctx_t *ctx, char **output_out) {
    char path[LDMD_MAX_PATH];
    snprintf(path, sizeof(path), "%s/templates/%s", web_root, template_name);
    
    char *tpl = NULL;
    ldmd_error_t err = template_load_file(path, &tpl);
    if (err != LDMD_OK) {
        LOG_ERROR("Failed to load template: %s", path);
        return err;
    }
    
    err = template_process(tpl, ctx, output_out);
    free(tpl);
    
    return err;
}

ldmd_error_t template_render_with_layout(const char *web_root, const char *template_name,
                                         template_ctx_t *ctx, char **output_out) {
    // First render the content template
    char *content = NULL;
    ldmd_error_t err = template_render(web_root, template_name, ctx, &content);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Set content for layout
    template_set(ctx, "content", content);
    free(content);
    
    // Render layout
    return template_render(web_root, "layout.html", ctx, output_out);
}

ldmd_error_t template_html_escape(const char *str, char **escaped_out) {
    if (!str) {
        *escaped_out = utils_strdup("");
        return LDMD_OK;
    }
    
    size_t len = strlen(str);
    size_t capacity = len * 6 + 1;  // Worst case: all & -> &amp;
    char *escaped = malloc(capacity);
    if (!escaped) return LDMD_ERROR_MEMORY;
    
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        switch (str[i]) {
            case '&':
                strcpy(escaped + pos, "&amp;");
                pos += 5;
                break;
            case '<':
                strcpy(escaped + pos, "&lt;");
                pos += 4;
                break;
            case '>':
                strcpy(escaped + pos, "&gt;");
                pos += 4;
                break;
            case '"':
                strcpy(escaped + pos, "&quot;");
                pos += 6;
                break;
            case '\'':
                strcpy(escaped + pos, "&#39;");
                pos += 5;
                break;
            default:
                escaped[pos++] = str[i];
        }
    }
    escaped[pos] = '\0';
    
    *escaped_out = escaped;
    return LDMD_OK;
}

ldmd_error_t template_json_escape(const char *str, char **escaped_out) {
    if (!str) {
        *escaped_out = utils_strdup("");
        return LDMD_OK;
    }
    
    size_t len = strlen(str);
    size_t capacity = len * 6 + 1;
    char *escaped = malloc(capacity);
    if (!escaped) return LDMD_ERROR_MEMORY;
    
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        switch (str[i]) {
            case '"':
                escaped[pos++] = '\\';
                escaped[pos++] = '"';
                break;
            case '\\':
                escaped[pos++] = '\\';
                escaped[pos++] = '\\';
                break;
            case '\n':
                escaped[pos++] = '\\';
                escaped[pos++] = 'n';
                break;
            case '\r':
                escaped[pos++] = '\\';
                escaped[pos++] = 'r';
                break;
            case '\t':
                escaped[pos++] = '\\';
                escaped[pos++] = 't';
                break;
            default:
                escaped[pos++] = str[i];
        }
    }
    escaped[pos] = '\0';
    
    *escaped_out = escaped;
    return LDMD_OK;
}
