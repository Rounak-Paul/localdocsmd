#!/bin/bash
# Download vendor libraries for LocalDocsMD

set -e

VENDOR_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$VENDOR_DIR"

echo "Downloading vendor libraries..."

# Mongoose - MIT License
# https://github.com/cesanta/mongoose
echo "Downloading Mongoose..."
curl -sL "https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h" -o mongoose.h
curl -sL "https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c" -o mongoose.c

# cJSON - MIT License
# https://github.com/DaveGamble/cJSON
echo "Downloading cJSON..."
curl -sL "https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h" -o cJSON.h
curl -sL "https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c" -o cJSON.c

# md4c - MIT License
# https://github.com/mity/md4c
echo "Downloading md4c..."
curl -sL "https://raw.githubusercontent.com/mity/md4c/master/src/md4c.h" -o md4c.h
curl -sL "https://raw.githubusercontent.com/mity/md4c/master/src/md4c.c" -o md4c.c
curl -sL "https://raw.githubusercontent.com/mity/md4c/master/src/md4c-html.h" -o md4c-html.h
curl -sL "https://raw.githubusercontent.com/mity/md4c/master/src/md4c-html.c" -o md4c-html.c
curl -sL "https://raw.githubusercontent.com/mity/md4c/master/src/entity.h" -o entity.h
curl -sL "https://raw.githubusercontent.com/mity/md4c/master/src/entity.c" -o entity.c

echo ""
echo "Vendor libraries downloaded successfully!"
echo ""
echo "Files:"
ls -la *.c *.h 2>/dev/null || echo "No files found"
