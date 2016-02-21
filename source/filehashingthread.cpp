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

#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include "filehashingthread.h"

CFileHashingThread::CFileHashingThread()
{
 m_BlockSize = 0x100000;
 m_HashFunction = NULL;
 m_Paused = false;
 m_Cancelled = false;
 m_FileStatus = true;
}

void CFileHashingThread::compute(const QString& filePath, const CCryptographicHash::Algorithm hashType)
{
 if (NULL == m_HashFunction)
 {
  m_FilePath = filePath;
  m_FileInfo.setFile(m_FilePath);
  m_HashFunction = new CCryptographicHash(hashType,m_FileInfo.size());
 }
 m_Paused = false; m_Cancelled = false;
}

void CFileHashingThread::pause(void)
{
 m_Paused = true;
}

void CFileHashingThread::resume(void)
{
 m_Paused = false;
}

void CFileHashingThread::cancel(void)
{
 if (isRunning())
 {
  m_Cancelled = true;
  m_Paused = false;
 }
}

void CFileHashingThread::run(void)
{
 while (!m_Cancelled)
 {
  while (m_Paused)
  {
   msleep(100);
  }
  if (NULL != m_HashFunction)
  {
   QFile file(m_FilePath);
   if (file.open(QIODevice::ReadOnly))
   {
    m_FileSize = file.size();
    emit begin();
    while (!m_Cancelled)
    {
     while (m_Paused)
     {
      msleep(100);
     }
     m_HashFunction->addData(file.read(m_BlockSize));
     m_FileProgress = (int)(100.0*file.pos()/file.size());
     emit update();
     if (file.pos() == file.size()) break;
    }
    file.close();
    m_FileHash = m_HashFunction->result();
    m_FileStatus = true;
   }
   else
   {
    m_FileStatus = false;
   }
   delete m_HashFunction;
   m_HashFunction = NULL;
   emit done();
  }
#if QT_VERSION >= 0x040500
  yieldCurrentThread();
#else
#ifdef Q_OS_UNIX
  sched_yield();
#endif
#ifdef Q_OS_WINDOWS
  SwitchToThread();
#endif
#endif
 }
 m_Paused = false;
 m_Cancelled = false;
}

