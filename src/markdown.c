#include "markdown.h"
#include "utils.h"
#include "md4c.h"
#include "md4c-html.h"
#include <stdlib.h>
#include <string.h>

// Buffer for HTML output
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} html_buffer_t;

static void html_buffer_append(html_buffer_t *buf, const char *text, size_t size) {
    if (buf->size + size + 1 > buf->capacity) {
        size_t new_capacity = (buf->capacity + size + 1) * 2;
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) return;
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    memcpy(buf->data + buf->size, text, size);
    buf->size += size;
    buf->data[buf->size] = '\0';
}

static void md_callback(const MD_CHAR *text, MD_SIZE size, void *userdata) {
    html_buffer_t *buf = (html_buffer_t *)userdata;
    html_buffer_append(buf, text, size);
}

ldmd_error_t markdown_render(const char *markdown, char **html_out) {
    if (!markdown || !html_out) {
        return LDMD_ERROR_INVALID;
    }
    
    html_buffer_t buf = {0};
    buf.capacity = strlen(markdown) * 2 + 1024;
    buf.data = malloc(buf.capacity);
    if (!buf.data) {
        return LDMD_ERROR_MEMORY;
    }
    buf.data[0] = '\0';
    buf.size = 0;
    
    // Convert markdown to HTML
    int ret = md_html(markdown, strlen(markdown), md_callback, &buf,
                      MD_FLAG_TABLES | MD_FLAG_STRIKETHROUGH | 
                      MD_FLAG_TASKLISTS | MD_FLAG_PERMISSIVEAUTOLINKS |
                      MD_FLAG_NOHTML,  // Don't allow raw HTML for security
                      0);
    
    if (ret != 0) {
        free(buf.data);
        return LDMD_ERROR;
    }
    
    *html_out = buf.data;
    return LDMD_OK;
}

ldmd_error_t markdown_render_page(const char *markdown, const char *title, char **html_out) {
    char *content_html = NULL;
    ldmd_error_t err = markdown_render(markdown, &content_html);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Build full HTML page
    const char *page_template = 
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "  <title>%s</title>\n"
        "  <link rel=\"stylesheet\" href=\"/static/css/markdown.css\">\n"
        "</head>\n"
        "<body>\n"
        "  <article class=\"markdown-body\">\n"
        "%s\n"
        "  </article>\n"
        "</body>\n"
        "</html>\n";
    
    size_t len = strlen(page_template) + strlen(title) + strlen(content_html) + 1;
    char *html = malloc(len);
    if (!html) {
        free(content_html);
        return LDMD_ERROR_MEMORY;
    }
    
    snprintf(html, len, page_template, title ? title : "Document", content_html);
    free(content_html);
    
    *html_out = html;
    return LDMD_OK;
}

ldmd_error_t markdown_extract_title(const char *markdown, char **title_out) {
    if (!markdown || !title_out) {
        return LDMD_ERROR_INVALID;
    }
    
    // Look for first H1 (# Title)
    const char *p = markdown;
    while (*p) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        
        // Check for H1
        if (*p == '#' && *(p+1) == ' ') {
            p += 2;
            const char *start = p;
            while (*p && *p != '\n' && *p != '\r') p++;
            
            size_t len = p - start;
            char *title = malloc(len + 1);
            if (!title) {
                return LDMD_ERROR_MEMORY;
            }
            strncpy(title, start, len);
            title[len] = '\0';
            
            // Trim whitespace
            char *trimmed = utils_trim(title);
            if (trimmed != title) {
                memmove(title, trimmed, strlen(trimmed) + 1);
            }
            
            *title_out = title;
            return LDMD_OK;
        }
        
        // Skip to next line
        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    
    return LDMD_ERROR_NOT_FOUND;
}

ldmd_error_t markdown_sanitize(const char *markdown, char **sanitized_out) {
    // For now, just copy the input
    // In production, you'd want to strip potentially dangerous content
    *sanitized_out = utils_strdup(markdown);
    if (!*sanitized_out) {
        return LDMD_ERROR_MEMORY;
    }
    return LDMD_OK;
}
