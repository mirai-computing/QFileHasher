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

#include "cryptohash.h"

CCryptographicHash::CCryptographicHash(Algorithm method, const qint64 size)
{
 m_Method = method;
#ifdef FEATURE_LIB_RHASH
 switch (m_Method)
 {
  case Crc32: { m_Context_rhash.flags = rhash::FLAG_CRC32; break; }
  case Md5:   { m_Context_rhash.flags = rhash::FLAG_MD5; break; }
  case Ed2k:  { m_Context_rhash.flags = rhash::FLAG_ED2K; break; }
  case Sha1:  { m_Context_rhash.flags = rhash::FLAG_SHA1; break; }
#ifdef FEATURE_LIB_RHASH_TIGER
  case Tiger: { m_Context_rhash.flags = rhash::FLAG_TIGER; break; }
#endif
  case Tth:   { m_Context_rhash.flags = rhash::FLAG_TTH; break; }
  case Aich:  { m_Context_rhash.flags = rhash::FLAG_AICH; break; }
 }
#endif
#ifdef FEATURE_LIB_SHA2
 //
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 //
#endif
#ifdef FEATURE_QT_HASH
 m_QtHash = NULL;
 switch (method)
 {
  case Md4:
#ifdef FEATURE_PREFER_QT_NATIVE_HASH
  case Md5:
  case Sha1:
#endif
  {
   m_QtHash = new QCryptographicHash(qtAlgorithm(method));
   break;
  }
 }
#endif
 reset(size);
}

CCryptographicHash::~CCryptographicHash()
{
#ifdef FEATURE_QT_HASH
 if (m_QtHash) delete m_QtHash;
#endif
}

void CCryptographicHash::reset(const qint64 size)
{
#ifdef FEATURE_LIB_RHASH
 crc_sums_init(&m_Context_rhash.state,m_Context_rhash.flags,size);
#endif
#ifdef FEATURE_LIB_SHA2
 switch (m_Method)
 {
  case Sha224: { sha2::sha256init(&m_Context_sha2.sha256state,true); break; }
  case Sha256: { sha2::sha256init(&m_Context_sha2.sha256state,false); break; }
  case Sha384: { sha2::sha512init(&m_Context_sha2.sha512state,true); break; }
  case Sha512: { sha2::sha512init(&m_Context_sha2.sha512state,false); break; }
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 switch (m_Method)
 {
#ifdef FEATURE_LIB_TOMCRYPT_MD2
  case Md2: { ltc::ltc_md2_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD4
  case Md4: { ltc::ltc_md4_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD5
  case Md5: { ltc::ltc_md5_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA1
  case Sha1: { ltc::ltc_sha1_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_TIGER
  case Tiger: { ltc::ltc_tiger_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA224
  case Sha224: { ltc::ltc_sha224_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA256
  case Sha256: { ltc::ltc_sha256_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA384
  case Sha384: { ltc::ltc_sha384_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA512
  case Sha512: { ltc::ltc_sha512_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD128
  case Rmd128: { ltc::ltc_rmd128_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD160
  case Rmd160: { ltc::ltc_rmd160_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD256
  case Rmd256: { ltc::ltc_rmd256_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD320
  case Rmd320: { ltc::ltc_rmd320_init(&m_Context_ltc.state); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_WHIRLPOOL
  case Whirlpool: { ltc::ltc_whirlpool_init(&m_Context_ltc.state); break; }
#endif
 }
#endif
#ifdef FEATURE_QT_HASH
 if (m_QtHash) m_QtHash->reset();
#endif
 m_Result.clear();
}

void CCryptographicHash::addData(const char *data, int length)
{
#ifdef FEATURE_LIB_RHASH
#ifdef FEATURE_QT_HASH
 if (!m_QtHash)
#endif
 rhash::crc_sums_update(&m_Context_rhash.state,(const unsigned char *)data,length);
#endif
#ifdef FEATURE_LIB_SHA2
 switch (m_Method)
 {
  case Sha224:
  case Sha256: { sha2::sha256(&m_Context_sha2.sha256state,(sha2::uchar *)data,length); break; }
  case Sha384:
  case Sha512: { sha2::sha512(&m_Context_sha2.sha512state,(sha2::uchar *)data,length); break; }
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 switch (m_Method)
 {
  case Md2: { ltc::ltc_md2_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
#ifdef FEATURE_LIB_TOMCRYPT_MD4
  case Md4: { ltc::ltc_md4_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD5
  case Md5: { ltc::ltc_md5_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA1
  case Sha1: { ltc::ltc_sha1_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_TIGER
  case Tiger: { ltc::ltc_tiger_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
#endif
  case Sha224: { ltc::ltc_sha224_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Sha256: { ltc::ltc_sha256_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Sha384: { ltc::ltc_sha384_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Sha512: { ltc::ltc_sha512_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Rmd128: { ltc::ltc_rmd128_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Rmd160: { ltc::ltc_rmd160_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Rmd256: { ltc::ltc_rmd256_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Rmd320: { ltc::ltc_rmd320_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
  case Whirlpool: { ltc::ltc_whirlpool_process(&m_Context_ltc.state,(const unsigned char *)data,length); break; }
 }
#endif
#ifdef FEATURE_QT_HASH
 if (m_QtHash) m_QtHash->addData(data,length);
#endif
}

void CCryptographicHash::addData(const QByteArray &data)
{
 addData(data.constData(), data.length());
}

QByteArray CCryptographicHash::result()
{
#ifdef FEATURE_LIB_RHASH
 {
  rhash::crc_context context = m_Context_rhash.state;
  rhash::crc_sums_final(&context,(rhash::crc_sums *)&m_Context_rhash.digest);
 }
 switch (m_Method)
 {
  case Crc32:
  {
   QByteArray tmp((const char *)&m_Context_rhash.digest.crc32,
                   sizeof(m_Context_rhash.digest.crc32));
   m_Result.resize(tmp.size());
   for (int i = 0, n = tmp.size(), j = n-1; i < n; i++,j--) m_Result[j] = tmp[i];
   break;
  }
  case Md5:
  {
#ifdef FEATURE_QT_HASH
   if (!m_QtHash)
#endif
   m_Result = QByteArray((const char *)&m_Context_rhash.digest.md5_digest,
                         sizeof(m_Context_rhash.digest.md5_digest));
   break;
  }
  case Sha1:
  {
#ifdef FEATURE_QT_HASH
   if (!m_QtHash)
#endif
   m_Result = QByteArray((const char *)&m_Context_rhash.digest.sha1_digest,
                         sizeof(m_Context_rhash.digest.sha1_digest));
   break;
  }
  case Ed2k:
  {
   m_Result = QByteArray((const char *)&m_Context_rhash.digest.ed2k_digest,
                         sizeof(m_Context_rhash.digest.ed2k_digest));
   break;
  }
#ifdef FEATURE_LIB_RHASH_TIGER
  case Tiger:
  {
   m_Result = QByteArray((const char *)&m_Context_rhash.digest.tiger_digest,
                         sizeof(m_Context_rhash.digest.tiger_digest));
   break;
  }
#endif
  case Tth:
  {
   m_Result = QByteArray((const char *)&m_Context_rhash.digest.tth_digest,
                         sizeof(m_Context_rhash.digest.tth_digest));
   break;
  }
  case Aich:
  {
   m_Result = QByteArray((const char *)&m_Context_rhash.digest.aich_digest,
                         sizeof(m_Context_rhash.digest.aich_digest));
   break;
  }
  default:    { break; }
 }
#endif
#ifdef FEATURE_LIB_SHA2
 switch (m_Method)
 {
  case Sha224:
  {
   sha2::SHA256state context = m_Context_sha2.sha256state;
   sha2::sha256finish(&context,(sha2::uchar *)&m_Context_sha2.sha224digest);
   m_Result = QByteArray((const char *)&m_Context_sha2.sha224digest,
                         sizeof(m_Context_sha2.sha224digest));
   break;
  }
  case Sha256:
  {
   sha2::SHA256state context = m_Context_sha2.sha256state;
   sha2::sha256finish(&context,(sha2::uchar *)&m_Context_sha2.sha256digest);
   m_Result = QByteArray((const char *)&m_Context_sha2.sha256digest,
                         sizeof(m_Context_sha2.sha256digest));
   break;
  }
  case Sha384:
  {
   sha2::SHA512state context = m_Context_sha2.sha512state;
   sha2::sha512finish(&context,(sha2::uchar *)&m_Context_sha2.sha384digest);
   m_Result = QByteArray((const char *)&m_Context_sha2.sha384digest,
                         sizeof(m_Context_sha2.sha384digest));
   break;
  }
  case Sha512:
  {
   sha2::SHA512state context = m_Context_sha2.sha512state;
   sha2::sha512finish(&context,(sha2::uchar *)&m_Context_sha2.sha512digest);
   m_Result = QByteArray((const char *)&m_Context_sha2.sha512digest,
                         sizeof(m_Context_sha2.sha512digest));
  }
 }
#endif
#ifdef FEATURE_LIB_TOMCRYPT
 switch (m_Method)
 {
  case Md2:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_md2_done(&context.state,(unsigned char *)&m_Context_ltc.md2digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.md2digest,
                         sizeof(m_Context_ltc.md2digest));
   break;
  }
#ifdef FEATURE_LIB_TOMCRYPT_MD4
  case Md4:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_md4_done(&context.state,(unsigned char *)&m_Context_ltc.md4digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.md4digest,
                         sizeof(m_Context_ltc.md4digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_MD5
  case Md5:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_md5_done(&context.state,(unsigned char *)&m_Context_ltc.md4digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.md5digest,
                         sizeof(m_Context_ltc.md5digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA1
  case Sha1:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_sha1_done(&context.state,(unsigned char *)&m_Context_ltc.sha1digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.sha1digest,
                         sizeof(m_Context_ltc.sha1digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_TIGER
  case Tiger:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_tiger_done(&context.state,(unsigned char *)&m_Context_ltc.tiger_digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.tiger_digest,
                         sizeof(m_Context_ltc.tiger_digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA224
  case Sha224:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_sha224_done(&context.state,(unsigned char *)&m_Context_ltc.sha224digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.sha224digest,
                         sizeof(m_Context_ltc.sha224digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA256
  case Sha256:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_sha256_done(&context.state,(unsigned char *)&m_Context_ltc.sha256digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.sha256digest,
                         sizeof(m_Context_ltc.sha256digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA384
  case Sha384:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_sha384_done(&context.state,(unsigned char *)&m_Context_ltc.sha384digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.sha384digest,
                         sizeof(m_Context_ltc.sha384digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_SHA512
  case Sha512:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_sha512_done(&context.state,(unsigned char *)&m_Context_ltc.sha512digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.sha512digest,
                         sizeof(m_Context_ltc.sha512digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD128
  case Rmd128:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_rmd128_done(&context.state,(unsigned char *)&m_Context_ltc.rmd128digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.rmd128digest,
                         sizeof(m_Context_ltc.rmd128digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD160
  case Rmd160:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_rmd160_done(&context.state,(unsigned char *)&m_Context_ltc.rmd160digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.rmd160digest,
                         sizeof(m_Context_ltc.rmd160digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD256
  case Rmd256:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_rmd256_done(&context.state,(unsigned char *)&m_Context_ltc.rmd256digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.rmd256digest,
                         sizeof(m_Context_ltc.rmd256digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_RMD320
  case Rmd320:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_rmd320_done(&context.state,(unsigned char *)&m_Context_ltc.rmd320digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.rmd320digest,
                         sizeof(m_Context_ltc.rmd320digest));
   break;
  }
#endif
#ifdef FEATURE_LIB_TOMCRYPT_WHIRLPOOL
  case Whirlpool:
  {
   ltc_context_t context = m_Context_ltc;
   ltc::ltc_whirlpool_done(&context.state,(unsigned char *)&m_Context_ltc.whirlpool_digest);
   m_Result = QByteArray((const char *)&m_Context_ltc.whirlpool_digest,
                         sizeof(m_Context_ltc.whirlpool_digest));
   break;
  }
#endif
 }
#endif
#ifdef FEATURE_QT_HASH
 if (m_QtHash) return m_QtHash->result();
#endif
 return m_Result;
}

QByteArray CCryptographicHash::hash(const QByteArray &data, Algorithm method)
{
 CCryptographicHash hash(method);
 hash.addData(data);
 return hash.result();
}

//

CCryptographicHash::Algorithm CCryptographicHash::algorithm(const QString& name)
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

QString CCryptographicHash::name(const Algorithm algorithm)
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

QString CCryptographicHash::description(const Algorithm algorithm)
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

QString CCryptographicHash::extension(const Algorithm algorithm)
{
 switch (algorithm)
 {
#ifdef FEATURE_LIB_RHASH_CRC32
  case Crc32: return "sfv";
#endif
  default:    return name(algorithm).toLower();
 }
}

#ifdef FEATURE_QT_HASH
CCryptographicHash::Algorithm
CCryptographicHash::algorithm(const QCryptographicHash::Algorithm qtAlgorithm)
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
CCryptographicHash::qtAlgorithm(const CCryptographicHash::Algorithm algorithm)
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

