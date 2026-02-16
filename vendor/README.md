# Vendor Libraries

This directory contains third-party libraries required by LocalDocsMD.

## Required Libraries

1. **Mongoose** - Embedded web server library
   - Website: https://github.com/cesanta/mongoose
   - License: MIT (dual licensed with GPLv2)
   - Files: `mongoose.h`, `mongoose.c`

2. **cJSON** - Lightweight JSON parser
   - Website: https://github.com/DaveGamble/cJSON
   - License: MIT
   - Files: `cJSON.h`, `cJSON.c`

3. **md4c** - Markdown parser
   - Website: https://github.com/mity/md4c
   - License: MIT
   - Files: `md4c.h`, `md4c.c`, `md4c-html.h`, `md4c-html.c`

## Automatic Download

Run the download script to fetch all libraries:

```bash
chmod +x download.sh
./download.sh
```

## Manual Download

If the script doesn't work, download manually:

### Mongoose
```bash
curl -O https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h
curl -O https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c
```

### cJSON
```bash
curl -O https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h
curl -O https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c
```

### md4c
```bash
curl -O https://raw.githubusercontent.com/mity/md4c/master/src/md4c.h
curl -O https://raw.githubusercontent.com/mity/md4c/master/src/md4c.c
curl -O https://raw.githubusercontent.com/mity/md4c/master/src/md4c-html.h
curl -O https://raw.githubusercontent.com/mity/md4c/master/src/md4c-html.c
```

## Building

After downloading the vendor libraries, build the project from the root directory:

```bash
mkdir build && cd build
cmake ..
make
```
