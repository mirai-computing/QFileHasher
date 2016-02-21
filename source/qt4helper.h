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

#ifndef QT4HELPER_H
#define QT4HELPER_H

#include <QtCore/QString>
#include <QtCore/QThread>
#include <QtGui/QFontMetrics>

class CSleeper : public QThread
{
 public:
  static void sleep(unsigned long secs)
  {
   QThread::sleep(secs);
  }
  static void msleep(unsigned long msecs)
  {
   QThread::msleep(msecs);
  }
  static void usleep(unsigned long usecs)
  {
   QThread::usleep(usecs);
  }
};

/** \brief Shortens a string to desired visible width by replacing an inner
    part of the string with '~' (tilde) character. */
QString DecorateFileName(const QString& fileName,
 const QFontMetrics& fontMetrics, const int stringWidth);

/** \brief Converts number of bytes to string representation with appropriate
    size suffix (b,Kb,Mb,Gb,Tb). */
QString FileSizeToString(const qint64 fileSize, const int digits = 6, const int precision = 2);

#endif // QT4HELPER_H
