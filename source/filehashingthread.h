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

#ifndef FILEHASHINGTHREAD_H
#define FILEHASHINGTHREAD_H

#include <QtCore/QFileInfo>
#include <QtCore/QThread>
#include "cryptohash.h"

class CFileHashingThread : public QThread
{
 Q_OBJECT
 private:
  CCryptographicHash *m_HashFunction;
  QFileInfo m_FileInfo;
  QByteArray m_FileHash;
  QString m_FilePath;
  qint64 m_FileSize;
  qint64 m_BlockSize;
  int m_FileProgress;
  bool m_Cancelled;
  bool m_Paused;
  bool m_FileStatus;
 signals:
  void begin(void);
  void update(void);
  void done(void);
 public slots:
  void compute(const QString& filePath, const CCryptographicHash::Algorithm hashType);
  void pause(void);
  void resume(void);
  void cancel(void);
 public:
  int progress(void) { return m_FileProgress; }
  QString& filePath(void) { return m_FilePath; }
  qint64 fileSize(void) { return m_FileSize; }
  QByteArray fileHash(void) { return m_FileHash; }
  bool paused(void) { return m_Paused; }
  bool cancelled(void) { return m_Cancelled; }
  bool status(void) { return m_FileStatus; }
  void run(void);
  CFileHashingThread();
};

#endif // FILEHASHINGTHREAD_H
