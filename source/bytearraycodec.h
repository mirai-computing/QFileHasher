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

#ifndef BYTEARRAYCODEC_H
#define BYTEARRAYCODEC_H

#include <QtCore/QObject>
#include <QtCore/QString>

const QString Base16Alphabet    = "0123456789ABCDEF";
//                                 ^         ^    =
const QString Base16lowAlphabet = "0123456789abcdef";
//                                 ^         ^    =
const QString Base32Alphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
//                                 ^         ^         ^         ^ =
const QString Base32hexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
//                                 ^         ^         ^         ^ =
const QString Base64Alphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//                                 ^         ^         ^         ^         ^         ^         ^   =
const QString Base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
//                                 ^         ^         ^         ^         ^         ^         ^   =

class CByteArrayCodec : public QObject
{
 Q_OBJECT
public:
 enum Encoding
 {
  Base16,
  Base16low,
  Base32,
  Base32hex,
  Base64,
  Base64url,
  EncodingCount
 };
private:
 static QString encode(const QByteArray& data, const QString alphabet,
                       const int bitsPerBlock, const int blocksPerGroup);
 static QByteArray decode(const QString& data, const QString alphabet,
                          const int bitsPerBlock, const int blocksPerGroup);
public:
 static QString name(const Encoding encoding);
 static QString alphabet(const Encoding encoding);
 static bool detect(const QString& data, Encoding& encoding);
 static QByteArray fromString(const QString& data, const Encoding encoding);
 static QString toString(const QByteArray& data, const Encoding encoding);
public:
 CByteArrayCodec(void);
};

#endif // BYTEARRAYCODEC_H
