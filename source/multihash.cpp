/*
    QFileHasher * Cryptographic hash calculation and verification utility
    Copyright (C) 2009-2011 Mirai Computing (mirai.computing@gmail.com)

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

#include "multihash.h"

CCryptographicMultiHash::CCryptographicMultiHash(Algorithm method, const qint64 size)
{
 m_Dirty = false;
 m_Method = method;
 m_Methods.insert(method);
#ifdef FEATURE_LIB_RHASH
#ifdef FEATURE_LIB_RHASH_TIGER
#endif
#endif
 //
#ifdef FEATURE_LIB_SHA2
#endif
 //
#ifdef FEATURE_LIB_TOMCRYPT
#endif
 //
#ifdef FEATURE_QT_HASH
 m_QtHashMd4 = new QCryptographicHash(QCryptographicHash::Md4);
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
 m_QtHashMd5 = new QCryptographicHash(QCryptographicHash::Md5);
 m_QtHashSha1 = new QCryptographicHash(QCryptographicHash::Sha1);
#endif
#endif
 reset(size);
}

CCryptographicMultiHash::CCryptographicMultiHash(void)
{
 m_Dirty = false;
 m_Method = CCryptographicMultiHash::AlgorithmCount;
#ifdef FEATURE_QT_HASH
 m_QtHashMd4 = new QCryptographicHash(QCryptographicHash::Md4);
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
 m_QtHashMd5 = new QCryptographicHash(QCryptographicHash::Md5);
 m_QtHashSha1 = new QCryptographicHash(QCryptographicHash::Sha1);
#endif
#endif
 reset();
}

CCryptographicMultiHash::~CCryptographicMultiHash()
{
#ifdef FEATURE_QT_HASH
 if (m_QtHashMd4) delete m_QtHashMd4;
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
 if (m_QtHashMd5) delete m_QtHashMd5;
 if (m_QtHashSha1) delete m_QtHashSha1;
#endif
#endif
}

QSet<CCryptographicMultiHash::Algorithm> CCryptographicMultiHash::methods(void)
{
 return m_Methods;
}

void CCryptographicMultiHash::enableMethod(Algorithm method)
{
 if (m_Dirty) return;
 if (!m_Methods.contains(method))
 {
  m_Methods.insert(method);
  reset(m_Size);
 }
}

void CCryptographicMultiHash::disableMethod(Algorithm method)
{
 if (m_Dirty) return;
 m_Methods.remove(method);
}

void CCryptographicMultiHash::enableAllMethods(void)
{
 if (m_Dirty) return;
 m_Methods.clear();
#ifdef FEATURE_LIB_RHASH_CRC32
 m_Methods.insert(Crc32);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD2
 m_Methods.insert(Md2);
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_TOMCRYPT_MD4
 m_Methods.insert(Md4);
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD5 || defined FEATURE_LIB_TOMCRYPT_MD5
 m_Methods.insert(Md5);
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_SHA1 || defined FEATURE_LIB_TOMCRYPT_SHA1
 m_Methods.insert(Sha1);
#endif
#if defined FEATURE_LIB_SHA2 || defined FEATURE_LIB_TOMCRYPT
 m_Methods.insert(Sha224);
 m_Methods.insert(Sha256);
 m_Methods.insert(Sha384);
 m_Methods.insert(Sha512);
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 m_Methods.insert(Rmd128);
 m_Methods.insert(Rmd160);
 m_Methods.insert(Rmd256);
 m_Methods.insert(Rmd320);
 m_Methods.insert(Whirlpool);
#endif
#if defined FEATURE_LIB_RHASH_TIGER || defined FEATURE_LIB_TOMCRYPT_TIGER
 m_Methods.insert(Tiger);
#endif
#ifdef FEATURE_LIB_RHASH
 m_Methods.insert(Ed2k);
 m_Methods.insert(Tth);
 m_Methods.insert(Aich);
#endif
 reset(m_Size);
}

void CCryptographicMultiHash::disableAllMethods(void)
{
 if (m_Dirty) return;
 m_Methods.clear();
}

void CCryptographicMultiHash::reset(const qint64 size)
{
 m_Size = size;
#ifdef FEATURE_LIB_RHASH
 int rhash_flags = 0;
 if (m_Methods.contains(Crc32)) { rhash_flags |= rhash::FLAG_CRC32; }
 if (m_Methods.contains(Md5))   { rhash_flags |= rhash::FLAG_MD5; }
 if (m_Methods.contains(Ed2k))  { rhash_flags |= rhash::FLAG_ED2K; }
 if (m_Methods.contains(Sha1))  { rhash_flags |= rhash::FLAG_SHA1; }
#ifdef FEATURE_LIB_RHASH_TIGER
 if (m_Methods.contains(Tiger)) { rhash_flags |= rhash::FLAG_TIGER; }
#endif
 if (m_Methods.contains(Tth))   { rhash_flags |= rhash::FLAG_TTH; }
 if (m_Methods.contains(Aich))  { rhash_flags |= rhash::FLAG_AICH; }
 m_Context_rhash.flags = (rhash::crc_sum_flags)rhash_flags;
 crc_sums_init(&m_Context_rhash.state,m_Context_rhash.flags,size);
#endif
#ifdef FEATURE_LIB_SHA2
 if (m_Methods.contains(Sha224)) sha2::sha256init(&m_Context_sha2.sha224state,true);
 if (m_Methods.contains(Sha256)) sha2::sha256init(&m_Context_sha2.sha256state,false);
 if (m_Methods.contains(Sha384)) sha2::sha512init(&m_Context_sha2.sha512state,true);
 if (m_Methods.contains(Sha512)) sha2::sha512init(&m_Context_sha2.sha512state,false);
#endif
#ifdef FEATURE_LIB_TOMCRYPT
#ifdef FEATURE_LIB_TOMCRYPT_MD2
 if (m_Methods.contains(Md2)) ltc::ltc_md2_init(&m_Context_ltc.md2state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD4
 if (m_Methods.contains(Md4)) ltc::ltc_md4_init(&m_Context_ltc.md4state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD5
 if (m_Methods.contains(Md5)) ltc::ltc_md5_init(&m_Context_ltc.md5state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA1
 if (m_Methods.contains(Sha1)) ltc::ltc_sha1_init(&m_Context_ltc.sha1state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_TIGER
 if (m_Methods.contains(Tiger)) ltc::ltc_tiger_init(&m_Context_ltc.tiger_state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA224
 if (m_Methods.contains(Sha224)) ltc::ltc_sha224_init(&m_Context_ltc.sha224state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA256
 if (m_Methods.contains(Sha256)) ltc::ltc_sha256_init(&m_Context_ltc.sha256state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA384
 if (m_Methods.contains(Sha384)) ltc::ltc_sha384_init(&m_Context_ltc.sha384state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA512
 if (m_Methods.contains(Sha512)) ltc::ltc_sha512_init(&m_Context_ltc.sha512state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD128
 if (m_Methods.contains(Rmd128)) ltc::ltc_rmd128_init(&m_Context_ltc.rmd128state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD160
 if (m_Methods.contains(Rmd160)) ltc::ltc_rmd160_init(&m_Context_ltc.rmd160state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD256
 if (m_Methods.contains(Rmd256)) ltc::ltc_rmd256_init(&m_Context_ltc.rmd256state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD320
 if (m_Methods.contains(Rmd320)) ltc::ltc_rmd320_init(&m_Context_ltc.rmd320state);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_WHIRLPOOL
 if (m_Methods.contains(Whirlpool)) ltc::ltc_whirlpool_init(&m_Context_ltc.whirlpool_state);
#endif
#endif
#ifdef FEATURE_QT_HASH
 if (m_QtHashMd4) m_QtHashMd4->reset();
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
 if (m_QtHashMd5) m_QtHashMd5->reset();
 if (m_QtHashSha1) m_QtHashSha1->reset();
#endif
#endif
 m_Result.clear();
 m_Dirty = false;
}

void CCryptographicMultiHash::addData(const char *data, int length)
{
#ifdef FEATURE_LIB_RHASH
#ifdef FEATURE_QT_HASH
 if (m_Methods.contains(Crc32)||
     m_Methods.contains(Tth)||m_Methods.contains(Aich)||
#ifdef FEATURE_LIB_RHASH_TIGER
     m_Methods.contains(Tiger)||
#endif
     (m_Methods.contains(Md4)&&(!m_QtHashMd4))||
     (m_Methods.contains(Md5)&&(!m_QtHashMd5))||
     (m_Methods.contains(Sha1)&&(!m_QtHashSha1)))
#endif
 rhash::crc_sums_update(&m_Context_rhash.state,(const unsigned char *)data,length);
#endif
#ifdef FEATURE_LIB_SHA2
 if (m_Methods.contains(Sha224)) sha2::sha256(&m_Context_sha2.sha224state,(sha2::uchar *)data,length);
 if (m_Methods.contains(Sha256)) sha2::sha256(&m_Context_sha2.sha256state,(sha2::uchar *)data,length);
 if (m_Methods.contains(Sha384)) sha2::sha512(&m_Context_sha2.sha384state,(sha2::uchar *)data,length);
 if (m_Methods.contains(Sha512)) sha2::sha512(&m_Context_sha2.sha512state,(sha2::uchar *)data,length);
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 if (m_Methods.contains(Md2)) ltc::ltc_md2_process(&m_Context_ltc.md2state,(const unsigned char *)data,length);
#ifdef FEATURE_LIB_TOMCRYPT_MD4
 if (m_Methods.contains(Md4)) ltc::ltc_md4_process(&m_Context_ltc.md4state,(const unsigned char *)data,length);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD5
 if (m_Methods.contains(Md5)) ltc::ltc_md5_process(&m_Context_ltc.md5state,(const unsigned char *)data,length);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA1
 if (m_Methods.contains(Sha1)) ltc::ltc_sha1_process(&m_Context_ltc.sha1state,(const unsigned char *)data,length);
#endif
#ifdef FEATURE_LIB_TOMCRYPT_TIGER
 if (m_Methods.contains(Tiger)) ltc::ltc_tiger_process(&m_Context_ltc.tiger_state,(const unsigned char *)data,length);
#endif
 if (m_Methods.contains(Sha224)) ltc::ltc_sha224_process(&m_Context_ltc.sha224state,(const unsigned char *)data,length);
 if (m_Methods.contains(Sha256)) ltc::ltc_sha256_process(&m_Context_ltc.sha256state,(const unsigned char *)data,length);
 if (m_Methods.contains(Sha384)) ltc::ltc_sha384_process(&m_Context_ltc.sha384state,(const unsigned char *)data,length);
 if (m_Methods.contains(Sha512)) ltc::ltc_sha512_process(&m_Context_ltc.sha512state,(const unsigned char *)data,length);
 if (m_Methods.contains(Rmd128)) ltc::ltc_rmd128_process(&m_Context_ltc.rmd128state,(const unsigned char *)data,length);
 if (m_Methods.contains(Rmd160)) ltc::ltc_rmd160_process(&m_Context_ltc.rmd160state,(const unsigned char *)data,length);
 if (m_Methods.contains(Rmd256)) ltc::ltc_rmd256_process(&m_Context_ltc.rmd256state,(const unsigned char *)data,length);
 if (m_Methods.contains(Rmd320)) ltc::ltc_rmd320_process(&m_Context_ltc.rmd320state,(const unsigned char *)data,length);
 if (m_Methods.contains(Whirlpool)) ltc::ltc_whirlpool_process(&m_Context_ltc.whirlpool_state,(const unsigned char *)data,length);
#endif
#ifdef FEATURE_QT_HASH
 if (m_Methods.contains(Md4) && m_QtHashMd4) m_QtHashMd4->addData(data,length);
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
 if (m_Methods.contains(Md5) && m_QtHashMd5) m_QtHashMd5->addData(data,length);
 if (m_Methods.contains(Sha1) && m_QtHashSha1) m_QtHashSha1->addData(data,length);
#endif
#endif
 m_Dirty = true;
}

void CCryptographicMultiHash::addData(const QByteArray &data)
{
 addData(data.constData(), data.length());
}

QByteArray CCryptographicMultiHash::result(Algorithm method)
{
 m_Result.clear();
#ifdef FEATURE_LIB_RHASH
 {
  rhash::crc_context context = m_Context_rhash.state;
  rhash::crc_sums_final(&context,(rhash::crc_sums *)&m_Context_rhash.digest);
 }
 if (m_Methods.contains(Crc32)&&(Crc32==method))
 {
  QByteArray tmp((const char *)&m_Context_rhash.digest.crc32,
                  sizeof(m_Context_rhash.digest.crc32));
  m_Result.resize(tmp.size());
  for (int i = 0, n = tmp.size(), j = n-1; i < n; i++,j--) m_Result[j] = tmp[i];
 }
 if (m_Methods.contains(Md5)&&(Md5==method))
 {
#ifdef FEATURE_QT_HASH
  if (!m_QtHashMd5)
#endif
  m_Result = QByteArray((const char *)&m_Context_rhash.digest.md5_digest,
                        sizeof(m_Context_rhash.digest.md5_digest));
 }
 if (m_Methods.contains(Sha1)&&(Sha1==method))
 {
#ifdef FEATURE_QT_HASH
  if (!m_QtHashSha1)
#endif
  m_Result = QByteArray((const char *)&m_Context_rhash.digest.sha1_digest,
                        sizeof(m_Context_rhash.digest.sha1_digest));
 }
 if (m_Methods.contains(Ed2k)&&(Ed2k==method))
 {
  m_Result = QByteArray((const char *)&m_Context_rhash.digest.ed2k_digest,
                        sizeof(m_Context_rhash.digest.ed2k_digest));
 }
#ifdef FEATURE_LIB_RHASH_TIGER
 if (m_Methods.contains(Tiger)&&(Tiger==method))
 {
  m_Result = QByteArray((const char *)&m_Context_rhash.digest.tiger_digest,
                        sizeof(m_Context_rhash.digest.tiger_digest));
 }
#endif
 if (m_Methods.contains(Tth)&&(Tth==method))
 {
  m_Result = QByteArray((const char *)&m_Context_rhash.digest.tth_digest,
                        sizeof(m_Context_rhash.digest.tth_digest));
 }
 if (m_Methods.contains(Aich)&&(Aich==method))
 {
  m_Result = QByteArray((const char *)&m_Context_rhash.digest.aich_digest,
                        sizeof(m_Context_rhash.digest.aich_digest));
 }
#endif
#ifdef FEATURE_LIB_SHA2
 if (m_Methods.contains(Sha224)&&(Sha224==method))
 {
  sha2::SHA256state context = m_Context_sha2.sha224state;
  sha2::sha256finish(&context,(sha2::uchar *)&m_Context_sha2.sha224digest);
  m_Result = QByteArray((const char *)&m_Context_sha2.sha224digest,
                        sizeof(m_Context_sha2.sha224digest));
 }
 if (m_Methods.contains(Sha256)&&(Sha256==method))
 {
  sha2::SHA256state context = m_Context_sha2.sha256state;
  sha2::sha256finish(&context,(sha2::uchar *)&m_Context_sha2.sha256digest);
  m_Result = QByteArray((const char *)&m_Context_sha2.sha256digest,
                        sizeof(m_Context_sha2.sha256digest));
 }
 if (m_Methods.contains(Sha384)&&(Sha384==method))
 {
  sha2::SHA512state context = m_Context_sha2.sha384state;
  sha2::sha512finish(&context,(sha2::uchar *)&m_Context_sha2.sha384digest);
  m_Result = QByteArray((const char *)&m_Context_sha2.sha384digest,
                        sizeof(m_Context_sha2.sha384digest));
 }
 if (m_Methods.contains(Sha512)&&(Sha512==method))
 {
  sha2::SHA512state context = m_Context_sha2.sha512state;
  sha2::sha512finish(&context,(sha2::uchar *)&m_Context_sha2.sha512digest);
  m_Result = QByteArray((const char *)&m_Context_sha2.sha512digest,
                        sizeof(m_Context_sha2.sha512digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 if (m_Methods.contains(Md2)&&(Md2==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_md2_done(&context.md2state,(unsigned char *)&m_Context_ltc.md2digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.md2digest,
                        sizeof(m_Context_ltc.md2digest));
 }
#ifdef FEATURE_LIB_TOMCRYPT_MD4
 if (m_Methods.contains(Md4)&&(Md4==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_md4_done(&context.md4state,(unsigned char *)&m_Context_ltc.md4digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.md4digest,
                        sizeof(m_Context_ltc.md4digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD5
 if (m_Methods.contains(Md5)&&(Md5==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_md5_done(&context.md5state,(unsigned char *)&m_Context_ltc.md4digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.md5digest,
                        sizeof(m_Context_ltc.md5digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA1
 if (m_Methods.contains(Sha1)&&(Sha1==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_sha1_done(&context.sha1state,(unsigned char *)&m_Context_ltc.sha1digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.sha1digest,
                        sizeof(m_Context_ltc.sha1digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_TIGER
 if (m_Methods.contains(Tiger)&&(Tiger==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_tiger_done(&context.tiger_state,(unsigned char *)&m_Context_ltc.tiger_digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.tiger_digest,
                        sizeof(m_Context_ltc.tiger_digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA224
 if (m_Methods.contains(Sha224)&&(Sha224==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_sha224_done(&context.sha224state,(unsigned char *)&m_Context_ltc.sha224digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.sha224digest,
                        sizeof(m_Context_ltc.sha224digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA256
 if (m_Methods.contains(Sha256)&&(Sha256==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_sha256_done(&context.sha256state,(unsigned char *)&m_Context_ltc.sha256digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.sha256digest,
                        sizeof(m_Context_ltc.sha256digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA384
 if (m_Methods.contains(Sha384)&&(Sha384==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_sha384_done(&context.sha384state,(unsigned char *)&m_Context_ltc.sha384digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.sha384digest,
                        sizeof(m_Context_ltc.sha384digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA512
 if (m_Methods.contains(Sha512)&&(Sha512==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_sha512_done(&context.sha512state,(unsigned char *)&m_Context_ltc.sha512digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.sha512digest,
                        sizeof(m_Context_ltc.sha512digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD128
 if (m_Methods.contains(Rmd128)&&(Rmd128==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_rmd128_done(&context.rmd128state,(unsigned char *)&m_Context_ltc.rmd128digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.rmd128digest,
                        sizeof(m_Context_ltc.rmd128digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD160
 if (m_Methods.contains(Rmd160)&&(Rmd160==method))
 {
  ltc_context_t context = m_Context_ltc;
  ltc::ltc_rmd160_done(&context.rmd160state,(unsigned char *)&m_Context_ltc.rmd160digest);
  m_Result = QByteArray((const char *)&m_Context_ltc.rmd160digest,
                        sizeof(m_Context_ltc.rmd160digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD256
 if (m_Methods.contains(Rmd256)&&(Rmd256==method))
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_rmd256_done(&context.rmd256state,(unsigned char *)&m_Context_ltc.rmd256digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.rmd256digest,
                         sizeof(m_Context_ltc.rmd256digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD320
 if (m_Methods.contains(Rmd320)&&(Rmd320==method))
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_rmd320_done(&context.rmd320state,(unsigned char *)&m_Context_ltc.rmd320digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.rmd320digest,
                         sizeof(m_Context_ltc.rmd320digest));
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_WHIRLPOOL
 if (m_Methods.contains(Whirlpool)&&(Whirlpool==method))
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_whirlpool_done(&context.whirlpool_state,(unsigned char *)&m_Context_ltc.whirlpool_digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.whirlpool_digest,
                         sizeof(m_Context_ltc.whirlpool_digest));
 }
#endif
#endif
#ifdef FEATURE_QT_HASH
 if (m_Methods.contains(Md4)&&(m_QtHashMd4)&&(Md4==method)) m_Result = m_QtHashMd4->result();
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
 if (m_Methods.contains(Md5)&&(m_QtHashMd5)&&(Md5==method)) m_Result = m_QtHashMd5->result();
 if (m_Methods.contains(Sha1)&&(m_QtHashSha1)&&(Sha1==method)) m_Result = m_QtHashSha1->result();
#endif
#endif
 return m_Result;
}

QByteArray CCryptographicMultiHash::hash(const QByteArray &data, Algorithm method)
{
 CCryptographicMultiHash hash(method);
 hash.addData(data);
 return hash.result(method);
}

QList<QByteArray> CCryptographicMultiHash::messageDigests
 (QList<CCryptographicMultiHash::Algorithm>& methods, QStringList& names)
{
 QList<QByteArray> digests;
 methods = m_Methods.toList();
 names.clear();
 for (int i = 0; i < methods.size(); i++)
 {
  names.append(name(methods[i]));
  digests.append(result(methods[i]));
 }
 return digests;
}

//

CCryptographicMultiHash::Algorithm CCryptographicMultiHash::algorithm(const QString& name)
{
#if defined FEATURE_LIB_RHASH_CRC32
 if (name == "CRC32") return Crc32;
#endif
#if defined FEATURE_LIB_TOMCRYPT_MD2
 if (name == "MD2")   return Md2;
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD4 || defined FEATURE_LIB_TOMCRYPT_MD4
 if (name == "MD4")   return Md4;
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD5 || defined FEATURE_LIB_TOMCRYPT_MD5
 if (name == "MD5")   return Md5;
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_SHA1 || defined FEATURE_LIB_TOMCRYPT_SHA1
 if (name == "SHA1")  return Sha1;
#endif
#if defined FEATURE_LIB_SHA2 || defined FEATURE_LIB_TOMCRYPT
 if (name == "SHA224")  return Sha224;
 if (name == "SHA256")  return Sha256;
 if (name == "SHA384")  return Sha384;
 if (name == "SHA512")  return Sha512;
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 if (name == "RIPEMD128")  return Rmd128;
 if (name == "RIPEMD160")  return Rmd160;
 if (name == "RIPEMD256")  return Rmd256;
 if (name == "RIPEMD320")  return Rmd320;
 if (name == "Whirlpool")  return Whirlpool;
#endif
#if defined FEATURE_LIB_RHASH_TIGER || defined FEATURE_LIB_TOMCRYPT_TIGER
 if (name == "Tiger") return Tiger;
#endif
#if defined FEATURE_LIB_RHASH
 if (name == "ED2K")  return Ed2k;
 if (name == "TTH")   return Tth;
 if (name == "AICH")  return Aich;
#endif
 return AlgorithmCount;
}

QString CCryptographicMultiHash::name(const Algorithm algorithm)
{
 switch (algorithm)
 {
#ifdef FEATURE_LIB_RHASH_CRC32
  case Crc32: return "CRC32";
#endif
#if defined FEATURE_LIB_TOMCRYPT_MD2
  case Md2:   return "MD2";
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD4 || defined FEATURE_LIB_TOMCRYPT_MD4
  case Md4:   return "MD4";
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD5 || defined FEATURE_LIB_TOMCRYPT_MD5
  case Md5:   return "MD5";
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_SHA1 || defined FEATURE_LIB_TOMCRYPT_SHA1
  case Sha1:  return "SHA1";
#endif
#if defined FEATURE_LIB_SHA2 || defined FEATURE_LIB_TOMCRYPT
  case Sha224: return "SHA224";
  case Sha256: return "SHA256";
  case Sha384: return "SHA384";
  case Sha512: return "SHA512";
#endif
#ifdef FEATURE_LIB_TOMCRYPT
  case Rmd128: return "RIPEMD128";
  case Rmd160: return "RIPEMD160";
  case Rmd256: return "RIPEMD256";
  case Rmd320: return "RIPEMD320";
  case Whirlpool: return "Whirlpool";
#endif
#if defined FEATURE_LIB_RHASH_TIGER || defined FEATURE_LIB_TOMCRYPT_TIGER
 case Tiger: return "Tiger";
#endif
#ifdef FEATURE_LIB_RHASH
  case Ed2k:  return "ED2K";
  case Tth:   return "TTH";
  case Aich:  return "AICH";
#endif
  default:    return "UNKNOWN";
 }
}

QString CCryptographicMultiHash::description(const Algorithm algorithm)
{
 switch (algorithm)
 {
#ifdef FEATURE_LIB_RHASH
  case Ed2k:  return "eDonkey ED2k";
  case Tth:   return "DC++ TTH";
#endif
  default:    return name(algorithm);
 }
}

QString CCryptographicMultiHash::extension(const Algorithm algorithm)
{
 switch (algorithm)
 {
#ifdef FEATURE_LIB_RHASH_CRC32
  case Crc32: return "sfv";
#endif
  default:    return name(algorithm).toLower();
 }
}

int CCryptographicMultiHash::digestSize(const Algorithm algorithm)
{
 switch (algorithm)
 {
#ifdef FEATURE_LIB_RHASH_CRC32
  case Crc32: return 4;
#endif
#if defined FEATURE_LIB_TOMCRYPT_MD2
  case Md2:   return 16;
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD4 || defined FEATURE_LIB_TOMCRYPT_MD4
  case Md4:   return 16;
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_MD5 || defined FEATURE_LIB_TOMCRYPT_MD5
  case Md5:   return 16;
#endif
#if defined FEATURE_QT_HASH || defined FEATURE_LIB_RHASH_SHA1 || defined FEATURE_LIB_TOMCRYPT_SHA1
  case Sha1:  return 20;
#endif
#if defined FEATURE_LIB_SHA2 || defined FEATURE_LIB_TOMCRYPT
  case Sha224: return 28;
  case Sha256: return 32;
  case Sha384: return 48;
  case Sha512: return 64;
#endif
#ifdef FEATURE_LIB_TOMCRYPT
  case Rmd128: return 16;
  case Rmd160: return 20;
  case Rmd256: return 16;
  case Rmd320: return 20;
  case Whirlpool: return 64;
#endif
#if defined FEATURE_LIB_RHASH_TIGER || defined FEATURE_LIB_TOMCRYPT_TIGER
 case Tiger: return 24;
#endif
#ifdef FEATURE_LIB_RHASH
  case Ed2k:  return 16;
  case Tth:   return 24;
  case Aich:  return 20;
#endif
  default:    return 0;
 }
}

bool CCryptographicMultiHash::detect(const QByteArray &message, const QByteArray &digest, Algorithm& method)
{
 for (int i = 0; i < CCryptographicMultiHash::AlgorithmCount; i++)
 {
  method = (CCryptographicMultiHash::Algorithm)i;
  if (digest.size() == digestSize(method))
  {
   QByteArray h = hash(message,method);
   if (h == digest)
   {
    return true;
   }
  }
 }
 return false;
}

#ifdef FEATURE_QT_HASH
CCryptographicMultiHash::Algorithm
CCryptographicMultiHash::algorithm(const QCryptographicHash::Algorithm qtAlgorithm)
{
 switch (qtAlgorithm)
 {
  case QCryptographicHash::Md4: return Md4;
  default:
  case QCryptographicHash::Md5: return Md5;
  case QCryptographicHash::Sha1: return Sha1;
 }
}

QCryptographicHash::Algorithm
CCryptographicMultiHash::qtAlgorithm(const CCryptographicMultiHash::Algorithm algorithm)
{
 switch (algorithm)
 {
  case Md4: return QCryptographicHash::Md4;
  default:
  case Md5: return QCryptographicHash::Md5;
  case Sha1: return QCryptographicHash::Sha1;
 }
}
#endif

