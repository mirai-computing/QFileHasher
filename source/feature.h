/*
    QFileHasher * A file hash calculation and verification utility
    Copyright (C) 2009 Mirai Computing (mirai.computing@gmail.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef FEATURE_H
#define FEATURE_H

#define FEATURE_LIB_RHASH
#ifdef FEATURE_LIB_RHASH
#define FEATURE_LIB_RHASH_CRC32
//#define FEATURE_LIB_RHASH_MD4
//#define FEATURE_LIB_RHASH_MD5
//#define FEATURE_LIB_RHASH_SHA1
//#define FEATURE_LIB_RHASH_TIGER
#define FEATURE_LIB_RHASH_ED2K
#define FEATURE_LIB_RHASH_AICH
#define FEATURE_LIB_RHASH_TTH
#endif
//#define FEATURE_LIB_SHA2
#define FEATURE_LIB_TOMCRYPT
#ifdef FEATURE_LIB_TOMCRYPT
#define FEATURE_LIB_TOMCRYPT_MD2
//#define FEATURE_LIB_TOMCRYPT_MD4
//#define FEATURE_LIB_TOMCRYPT_MD5
//#define FEATURE_LIB_TOMCRYPT_SHA1
#define FEATURE_LIB_TOMCRYPT_TIGER
#define FEATURE_LIB_TOMCRYPT_SHA224
#define FEATURE_LIB_TOMCRYPT_SHA256
#define FEATURE_LIB_TOMCRYPT_SHA384
#define FEATURE_LIB_TOMCRYPT_SHA512
#define FEATURE_LIB_TOMCRYPT_RMD128
#define FEATURE_LIB_TOMCRYPT_RMD160
#define FEATURE_LIB_TOMCRYPT_RMD256
#define FEATURE_LIB_TOMCRYPT_RMD320
#define FEATURE_LIB_TOMCRYPT_WHIRLPOOL
#endif
#define FEATURE_QT_HASH
#define FEATURE_PREFER_QT_NATIVE_HASH
//#define FEATURE_AUTOSCROLL

#endif // FEATURE_H
