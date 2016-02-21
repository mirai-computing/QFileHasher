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

#include <QtCore/QStringList>
#include "bytearraycodec.h"

CByteArrayCodec::CByteArrayCodec(void)
{
 //
}

QString CByteArrayCodec::encode(const QByteArray& data, const QString alphabet,
 const int bitsPerBlock, const int blocksPerGroup)
{
 const int bitsPerByte = 8;
 int bitsLeft = bitsPerByte*data.size(); // number of bits in 'data'
 /*int bitsPerBlock = 4;*/ // number of bits per block encoding a single position
 int bitsFetched = 0; // number of bits fetched from 'data' to current block
 int bitIndex = 0; // index of last yet unfetched bit
 int byteIndex = 0; // index of last yet unfetched byte
 int blockIndex = 0;
 //QString alphabet = Base16Alphabet;
 char padding = '=';
 //
 QString result;
 unsigned char blockData = 0;
 while (bitsLeft)
 {
  /*if (bitsFetched < bitsPerBlock)
  {*/
   int bitsAvailable = bitsPerByte - bitIndex;
   int bitsRequired = bitsPerBlock - bitsFetched;
   int bitsToFetch = (bitsAvailable < bitsRequired) ? bitsAvailable : bitsRequired;
   int bitShift1 = bitsAvailable - bitsToFetch;
   int bitShift2 = bitsRequired - bitsToFetch;
   unsigned char bitMask = ((1<<bitsToFetch)-1)<<bitShift1;
   unsigned char bitsSource = data.at(byteIndex);
   unsigned char bitsMasked = bitsSource&bitMask;
   unsigned char bitsEncoded = (bitsMasked>>bitShift1)<<bitShift2;
   blockData |= bitsEncoded;
   bitsFetched += bitsToFetch;
   bitIndex += bitsToFetch;
   bitsLeft -= bitsToFetch;
   if (bitIndex >= bitsPerByte)
   {
    byteIndex++;
    bitIndex = 0;
   }
   if (bitsFetched >= bitsPerBlock)
   {
    QChar c = alphabet.at(blockData);
    result.append(c);
    blockData = 0;
    bitsFetched = 0;
    blockIndex++;
    if (blockIndex >= blocksPerGroup) blockIndex = 0;
   }
  /*}*/
 }
 if (blockIndex) if (bitsFetched < bitsPerBlock)
 {
  QChar c = alphabet.at(blockData);
  result.append(c);
  blockIndex++;
  if (blockIndex >= blocksPerGroup) blockIndex = 0;
 }
 if (blockIndex) while (blockIndex < blocksPerGroup)
 {
  result.append(padding);
  blockIndex++;
 }
 return result;
}

QByteArray CByteArrayCodec::decode(const QString& data, const QString alphabet,
 const int bitsPerBlock, const int blocksPerGroup)
{
 int charMap[0x100]; char padding = '=';
 for (int i = 0; i < 0x100; i++) charMap[i] = -1;
 charMap[(unsigned char)padding] = 0;
 for (int i = 0; i < alphabet.size(); i++)
 {
  unsigned char c = alphabet.at(i).toAscii();
  charMap[c] = i;
 }
 //
 const int bitsPerByte = 8;
 int bitsLeft = bitsPerBlock*data.size(); // number of bits in 'data'
 /*int bitsPerBlock = 4;*/ // number of bits per block encoding a single position
 int bitsFetched = 0; // number of bits fetched from 'data' to current block
 int bitIndex = 0; // index of last yet unfetched bit
 //int byteIndex = 0; // index of last yet unfetched byte
 int blockIndex = 0;
 //
 QByteArray result;
 unsigned char byteData = 0;
 while (bitsLeft)
 {
  unsigned char charSource = (unsigned char)data.at(blockIndex).toAscii();
  if (padding==charSource) return result;
  int mappedSource = charMap[charSource];
  if (mappedSource<0)
  {
   result.clear();
   return result;
  }
  unsigned char bitsSource = (unsigned char)mappedSource;
  int bitsAvailable = bitsPerBlock - bitsFetched;
  int bitsRequired = bitsPerByte - bitIndex;
  int bitsToFetch = (bitsAvailable < bitsRequired) ? bitsAvailable : bitsRequired;
  int bitShift1 = bitsAvailable - bitsToFetch;
  int bitShift2 = bitsRequired - bitsToFetch;
  unsigned char bitMask = ((1<<bitsToFetch)-1)<<bitShift1;
  unsigned char bitsMasked = bitsSource&bitMask;
  unsigned char bitsDecoded = (bitsMasked>>bitShift1)<<bitShift2;
  byteData |= bitsDecoded;
  bitsFetched += bitsToFetch;
  bitIndex += bitsToFetch;
  bitsLeft -= bitsToFetch;
  if (bitIndex >= bitsPerByte)
  {
   result.append(byteData);
   byteData = 0;
   bitIndex = 0;
  }
  if (bitsFetched >= bitsPerBlock)
  {
   bitsFetched = 0;
   blockIndex++;
  }
 }
 return result;
}

QString CByteArrayCodec::name(const Encoding encoding)
{
 switch (encoding)
 {
  case CByteArrayCodec::Base16: return "Base16";
  case CByteArrayCodec::Base16low: return "Base16";
  case CByteArrayCodec::Base32: return "Base32";
  case CByteArrayCodec::Base32hex: return "Base32HEX";
  case CByteArrayCodec::Base64: return "Base64";
  case CByteArrayCodec::Base64url: return "Base16URL";
 }
 return "";
}

QString CByteArrayCodec::alphabet(const Encoding encoding)
{
 switch (encoding)
 {
  case CByteArrayCodec::Base16: return Base16Alphabet;
  case CByteArrayCodec::Base16low: return Base16lowAlphabet;
  case CByteArrayCodec::Base32: return Base32Alphabet;
  case CByteArrayCodec::Base32hex: return Base32hexAlphabet;
  case CByteArrayCodec::Base64: return Base64Alphabet;
  case CByteArrayCodec::Base64url: return Base64urlAlphabet;
 }
 return "";
}

bool CByteArrayCodec::detect(const QString& data,
 CByteArrayCodec::Encoding& encoding)
{
 for (int i = 0; i < CByteArrayCodec::EncodingCount; i++)
 {
  encoding = (CByteArrayCodec::Encoding)i;
  QString a = alphabet(encoding);
  bool charsFit = true;
  for (int j = 0; j < data.size(); j++)
  {
   if (!a.contains(data[j]))
   {
    charsFit = false;
    break;
   }
  }
  if (charsFit)
  {
   QByteArray b = fromString(data,encoding);
   if (!b.isEmpty()) return true;
  }
 }
 return false;
}

QByteArray CByteArrayCodec::fromString(const QString& data,
 const CByteArrayCodec::Encoding encoding)
{
 switch (encoding)
 {
  case CByteArrayCodec::Base16: return decode(data,Base16Alphabet,4,2);
  case CByteArrayCodec::Base16low: return decode(data,Base16lowAlphabet,4,2);
  case CByteArrayCodec::Base32: return decode(data,Base32Alphabet,5,8);
  case CByteArrayCodec::Base32hex: return decode(data,Base32hexAlphabet,5,8);
  case CByteArrayCodec::Base64: return decode(data,Base64Alphabet,6,4);
  case CByteArrayCodec::Base64url: return decode(data,Base64urlAlphabet,6,4);
 }
 return "";
}

QString CByteArrayCodec::toString(const QByteArray& data,
 const CByteArrayCodec::Encoding encoding)
{
 switch (encoding)
 {
  case CByteArrayCodec::Base16: return encode(data,Base16Alphabet,4,2);
  case CByteArrayCodec::Base16low: return encode(data,Base16lowAlphabet,4,2);
  case CByteArrayCodec::Base32: return encode(data,Base32Alphabet,5,8);
  case CByteArrayCodec::Base32hex: return encode(data,Base32hexAlphabet,5,8);
  case CByteArrayCodec::Base64: return encode(data,Base64Alphabet,6,4);
  case CByteArrayCodec::Base64url: return encode(data,Base64urlAlphabet,6,4);
 }
 return "";
}

bool test(void)
{
 QList<QByteArray> input;
 QStringList base16,base32,base32hex,base64;
 input  << "" << "f" << "fo" << "foo" << "foob" << "fooba" << "foobar";
 base16 << "" << "66" << "666F" << "666F6F" << "666F6F62" << "666F6F6261"
        << "666F6F626172";
 base32 << "" << "MY======" << "MZXQ====" << "MZXW6===" << "MZXW6YQ="
        << "MZXW6YTB" << "MZXW6YTBOI======";
 base32hex << "" << "CO======" << "CPNG====" << "CPNMU===" << "CPNMUOG="
           << "CPNMUOJ1" << "CPNMUOJ1E8======";
 base64 << "" << "Zg==" << "Zm8=" << "Zm9v" << "Zm9vYg==" << "Zm9vYmE="
        << "Zm9vYmFy";
 QList<CByteArrayCodec::Encoding> encodings;
 encodings << CByteArrayCodec::Base16 << CByteArrayCodec::Base32
           << CByteArrayCodec::Base32hex << CByteArrayCodec::Base64;
 //
 bool result = true;
 CByteArrayCodec c;
 for (int j = 0; j < encodings.size(); j++)
 {
  CByteArrayCodec::Encoding e = encodings.at(j);
  for (int i = 0; i < input.size(); i++)
  {
   QString s = c.toString(input.at(i),e);
   QString r = c.fromString(s,e);
   result &= (0 == QString::compare(s,base16.at(i),Qt::CaseSensitive));
   result &= (0 == QString::compare(r,input.at(i),Qt::CaseSensitive));
 }}
 return result;
}
