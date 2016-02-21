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

#ifndef CRYPTOHASH_H
#define CRYPTOHASH_H

#include <cstdlib>
#include <cstdio>
#include "feature.h"

#include <QtCore/QObject>
#include <QtCore/QByteArray>
#ifdef FEATURE_QT_HASH
#include <QtCore/QCryptographicHash>
#endif

#ifdef FEATURE_LIB_RHASH
namespace rhash
{
 #include "crc_sums.h"
}
#endif

#ifdef FEATURE_LIB_SHA2
namespace sha2
{
 #include "sha2.h"
}
#endif

#ifdef FEATURE_LIB_TOMCRYPT
namespace ltc
{
 #include "tomcrypt.h"
}
#endif

class CCryptographicHash : public QObject
{
 Q_OBJECT
 public:
  enum Algorithm {
#ifdef FEATURE_LIB_RHASH_CRC32
  Crc32,
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD2
  Md2,
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_TOMCRYPT_MD4
  Md4,
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD5 || defined FEATURE_LIB_TOMCRYPT_MD5
  Md5,
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_SHA1 || defined FEATURE_LIB_TOMCRYPT_SHA1
  Sha1,
#endif
#if defined FEATURE_LIB_SHA2 || defined FEATURE_LIB_TOMCRYPT
  Sha224, Sha256, Sha384, Sha512,
#endif
#ifdef FEATURE_LIB_TOMCRYPT
  Rmd128, Rmd160, Rmd256, Rmd320, Whirlpool,
#endif
#if defined FEATURE_LIB_RHASH_TIGER || defined FEATURE_LIB_TOMCRYPT_TIGER
  Tiger,
#endif
#ifdef FEATURE_LIB_RHASH
  Ed2k, Tth, Aich,
#endif
  AlgorithmCount
  };
 private:
  CCryptographicHash::Algorithm m_Method;
#ifdef FEATURE_LIB_RHASH
  struct rhash_context_t
  {
   rhash::crc_sum_flags flags;
   rhash::crc_context   state;
   rhash::crc_sums      digest;
  }
  m_Context_rhash;
#endif
#ifdef FEATURE_LIB_SHA2
  struct sha2_context_t
  {
   sha2::SHA256state sha256state;
   sha2::SHA512state sha512state;
   union
   {
    sha2::uchar sha224digest[sha2::SHA224dlen];
    sha2::uchar sha256digest[sha2::SHA256dlen];
    sha2::uchar sha384digest[sha2::SHA384dlen];
    sha2::uchar sha512digest[sha2::SHA512dlen];
   };
  }
  m_Context_sha2;
#endif
#ifdef FEATURE_LIB_TOMCRYPT
  struct ltc_context_t
  {
   ltc::hash_state  state;
   union
   {
    unsigned char md2digest[16]; //ltc::md2_desc.hashsize
    unsigned char md4digest[16];
    unsigned char md5digest[16];
    unsigned char sha1digest[20];
    unsigned char tiger_digest[24];
    unsigned char sha224digest[28];
    unsigned char sha256digest[32];
    unsigned char sha384digest[48];
    unsigned char sha512digest[64];
    unsigned char rmd128digest[16];
    unsigned char rmd160digest[20];
    unsigned char rmd256digest[16];
    unsigned char rmd320digest[20];
    unsigned char whirlpool_digest[64];
   };
  }
  m_Context_ltc;
#endif
#ifdef FEATURE_QT_HASH
  QCryptographicHash* m_QtHash;
#endif
  QByteArray m_Result;
 public:
  void reset(const qint64 size = 0);
  void addData(const char *data, int length);
  void addData(const QByteArray &data);
  QByteArray result();
  static QByteArray hash(const QByteArray &data, Algorithm method);
 public:
  static const int minHashLength = 8;
  /** \brief Returns hashing algorithm by its name. */
  static Algorithm algorithm(const QString& name);
  /** \brief Returns name of a hashing algorithm. */
  static QString name(const Algorithm algorithm);
  /** \brief Returns short description of a hashing algorithm. */
  static QString description(const Algorithm algorithm);
  /** \brief Returns favorable file extension of for checksum file. */
  static QString extension(const Algorithm algorithm);
#ifdef FEATURE_QT_HASH
  /** \brief Returns corresponding hashing algorithm for one of built-in Qt. */
  static Algorithm algorithm(const QCryptographicHash::Algorithm qtAlgorithm);
  /** \brief Returns built-in hashing algorithm. */
  static QCryptographicHash::Algorithm qtAlgorithm(const Algorithm algorithm);
#endif
 public:
  CCryptographicHash(Algorithm method, const qint64 size = 0);
  ~CCryptographicHash(void);
};

#endif
