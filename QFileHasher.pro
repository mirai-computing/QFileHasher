# -------------------------------------------------
# Project created by QtCreator 2009-06-21T16:44:18
# -------------------------------------------------
TARGET = QFileHasher
TEMPLATE = app
INCLUDEPATH += source \
    source/librhash \
    source/libtomcrypt/headers \
    source/libtomcrypt/hashes \
    source/libtomcrypt/hashes/helper \
    source/libtomcrypt/hashes/sha2 \
    source/libtomcrypt/hashes/whirl
SOURCES += source/main.cpp \
    source/mainwindow.cpp \
    source/filehashingthread.cpp \
    source/filehasher.cpp \
    source/cryptohash.cpp \
    source/qt4support.cpp \
    source/libtomcrypt/hashes/ltc_rmd320.c \
    source/libtomcrypt/hashes/ltc_rmd256.c \
    source/libtomcrypt/hashes/ltc_rmd160.c \
    source/libtomcrypt/hashes/ltc_rmd128.c \
    source/libtomcrypt/hashes/ltc_md2.c \
    source/libtomcrypt/hashes/ltc_md4.c \
    source/libtomcrypt/hashes/ltc_md5.c \
    source/libtomcrypt/hashes/helper/ltc_hash_memory_multi.c \
    source/libtomcrypt/hashes/helper/ltc_hash_memory.c \
    source/libtomcrypt/hashes/helper/ltc_hash_filehandle.c \
    source/libtomcrypt/hashes/helper/ltc_hash_file.c \
    source/libtomcrypt/misc/ltc_zeromem.c \
    source/libtomcrypt/misc/crypt/ltc_crypt_argchk.c \
    source/libtomcrypt/misc/crypt/ltc_crypt_hash_is_valid.c \
    source/libtomcrypt/misc/crypt/ltc_crypt_hash_descriptor.c \
    source/libtomcrypt/hashes/ltc_tiger.c \
    source/libtomcrypt/hashes/ltc_sha1.c \
    source/libtomcrypt/hashes/ltc_whirl.c \
    source/libtomcrypt/hashes/sha2/ltc_sha512.c \
    source/libtomcrypt/hashes/sha2/ltc_sha256.c \
    source/librhash/tth.c \
    source/librhash/tiger_data.c \
    source/librhash/tiger.c \
    source/librhash/sha1.c \
    source/librhash/md5.c \
    source/librhash/md4.c \
    source/librhash/hex.c \
    source/librhash/ed2k.c \
    source/librhash/crc_sums.c \
    source/librhash/crc32.c \
    source/librhash/byte_order.c \
    source/librhash/aich.c \
    source/bytearraycodec.cpp
HEADERS += source/mainwindow.h \
    source/filehashingthread.h \
    source/filehasher.h \
    source/cryptohash.h \
    source/qt4support.h \
    source/feature.h \
    source/libtomcrypt/headers/tomcrypt_misc.h \
    source/libtomcrypt/headers/tomcrypt_hash.h \
    source/libtomcrypt/headers/tomcrypt_custom.h \
    source/libtomcrypt/headers/tomcrypt_cfg.h \
    source/libtomcrypt/headers/tomcrypt.h \
    source/libtomcrypt/headers/tomcrypt_macros.h \
    source/libtomcrypt/headers/tomcrypt_argchk.h \
    source/librhash/tth.h \
    source/librhash/tiger.h \
    source/librhash/sha1.h \
    source/librhash/md5.h \
    source/librhash/md4.h \
    source/librhash/hex.h \
    source/librhash/ed2k.h \
    source/librhash/crc_sums.h \
    source/librhash/crc32.h \
    source/librhash/byte_order.h \
    source/librhash/aich.h \
    source/librhash/tiger.h \
    source/bytearraycodec.h
FORMS += source/mainwindow.ui
RESOURCES += source/main.qrc
TRANSLATIONS += source/qfilehasher_ru.ts
OTHER_FILES += todo.txt \
    changelog.txt
RC_FILE = source/qfilehasher.rc
