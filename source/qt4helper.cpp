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

#include <cmath>

#include "qt4helper.h"

QString DecorateFileName(const QString& fileName,
 const QFontMetrics& fontMetrics, const int stringWidth)
{
 if ((fileName.length() >= 1) && (stringWidth > 0))
 {
  double rawWidth = (double)(fontMetrics.width(fileName)+fontMetrics.width(" ~ "));
  double charRate = (double)fileName.length()/rawWidth;
  if (rawWidth > 0.0)
  {
   int halfLength = (int)floor(0.4*(double)stringWidth*charRate);
   return fileName.left(halfLength)+" ~ "+fileName.right(halfLength);
  }
 }
 return "";
}

QString FileSizeToString(const qint64 fileSize, const int digits, const int precision)
{
 const qint64 kb = 0x00000000400LL;
 const qint64 mb = 0x00000100000LL;
 const qint64 gb = 0x00040000000LL;
 const qint64 tb = 0x10000000000LL;
 if (fileSize <= kb)
 {
  return QString(QObject::tr("%1 b")).arg((double)fileSize,digits,'f',precision);
 }
 else if (fileSize <= mb)
 {
  return QString(QObject::tr("%1 Kb")).arg((double)fileSize/(double)kb,digits,'f',precision);
 }
 else if (fileSize <= gb)
 {
  return QString(QObject::tr("%1 Mb")).arg((double)fileSize/(double)mb,digits,'f',precision);
 }
 else if (fileSize <= tb)
 {
  return QString(QObject::tr("%1 Gb")).arg((double)fileSize/(double)gb,digits,'f',precision);
 }
 else
 {
  return QString(QObject::tr("%1 Tb")).arg((double)fileSize/(double)tb,digits,'f',precision);
 }
}


