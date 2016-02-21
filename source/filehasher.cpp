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

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTextCodec>
#include <QtCore/QTextStream>

#include "filehasher.h"
#include "qt4support.h"

CFileHasher::CFileHasher()
{
 QList<QByteArray> codecs = QTextCodec::availableCodecs();
 for (int i = 0, n = codecs.count(); i < n; i++)
 {
  QString codecName(codecs.at(i));
  m_TextEncodings << codecName;
 }
 setTextEncoding("UTF-8");
 setHashEncoding(CByteArrayCodec::Base16low);
 m_DoWriteHeader = true;
 m_DoWriteAsteriskDelimiter = true;
 m_DoWriteHashAlgorithm = false;
 m_CommentCharacter = QChar('#');
 m_DateTimeFormat = "dd.MM.yyyy hh:mm:ss";
 //
 m_HashAlgorithm = CCryptographicHash::Md5;
 setRootPath(QDir::rootPath());
 //
 connect(this,SIGNAL(startWorkerThread(QString,CCryptographicHash::Algorithm)),
         &m_HashingThread,SLOT(compute(QString,CCryptographicHash::Algorithm)));
 connect(&m_HashingThread,SIGNAL(begin()),this,SLOT(workerThreadStarted()));
 connect(&m_HashingThread,SIGNAL(update()),this,SLOT(workerThreadUpdated()));
 connect(&m_HashingThread,SIGNAL(done()),this,SLOT(workerThreadFinished()));
 //
 //m_HashingThread.start(QThread::LowestPriority);
}

QString CFileHasher::toNativeSeparators(QString pathName)
{
 return QDir::toNativeSeparators(pathName.replace('\\','/'));
}

QString CFileHasher::getListItem(QStringList& list, const int index)
{
 if ((index >= 0) && (index < list.count()))
 {
  return list.at(index);
 }
 else return "";
}

void CFileHasher::setTextEncoding(const QString& encoding)
{
 if (m_TextEncodings.indexOf(encoding)>=0)
 {
  m_TextEncoding = encoding;
 }
 else
 {
  m_TextEncoding = "UTF-8";
 }
}

CFileHasher::OperationMode CFileHasher::operationMode(void)
{
 return m_OperationMode;
}

void CFileHasher::setOperationMode(const CFileHasher::OperationMode mode)
{
 /* TODO: check operation state before changing mode. */
 m_OperationMode = mode;
}

CFileHasher::UpdateMode CFileHasher::updateMode(void)
{
 return m_UpdateMode;
}

void CFileHasher::setUpdateMode(const CFileHasher::UpdateMode mode)
{
 /* TODO: check operation state before changing mode. */
 m_UpdateMode = mode;
 selectFromSavedFiles();
 collectMissingAndExistingFiles();
 switch (mode)
 {
  case CFileHasher::Brief:
  {
   break;
  }
  case CFileHasher::Deep:
  {
   collectFileLevelDirectories();
   findNewFiles();
   break;
  }
  case CFileHasher::DeltaDeep:
  {
   collectFileLevelDirectories();
   findNewFiles();
   collectExclusivelyNewFiles();
   break;
  }
  case CFileHasher::Complete:
  {
   collectTopLevelDirectories();
   findNewFilesAndDirectories();
   //removeDuplicatesFromSelection();
   break;
  }
  case CFileHasher::DeltaComplete:
  {
   collectTopLevelDirectories();
   findNewFilesAndDirectories();
   collectExclusivelyNewFiles();
   //removeDuplicatesFromSelection();
   break;
  }
 }
}

QString CFileHasher::rootPath(void)
{
 return m_RootPath;
}

void CFileHasher::setRootPath(const QString& path)
{
 m_RootPath = toNativeSeparators(path);
 if (!m_RootPath.endsWith(QDir::separator()))
 {
  m_RootPath.append(QDir::separator());
 }
 m_RootDir.setPath(m_RootPath);
}

CCryptographicHash::Algorithm CFileHasher::hashAlgorithm(void)
{
 return m_HashAlgorithm;
}

void CFileHasher::setHashAlgorithm(CCryptographicHash::Algorithm algorithm)
{
 m_HashAlgorithm = algorithm;
}

CByteArrayCodec::Encoding CFileHasher::hashEncoding(void)
{
 return m_HashEncoding;
}

void CFileHasher::setHashEncoding(CByteArrayCodec::Encoding encoding)
{
 m_HashEncoding = encoding;
}

QString CFileHasher::statusName(const CFileHasher::FileStatus status)
{
 switch (status)
 {
  case CFileHasher::Good: return tr("Processed");
  case CFileHasher::NoAccess: return tr("Inaccessible");
  case CFileHasher::HashMatch: return tr("Checked");
  case CFileHasher::HashMismatch: return tr("Hash mismatch");
 }
 return "";
}

QString CFileHasher::filePath(const QString& fileName)
{
 return m_RootPath+fileName;
}

int CFileHasher::fileLevelDirectoriesCount(void)
{
 return m_FileLevelDirectories.count();
}

QString CFileHasher::fileLevelDirectory(const int index)
{
 return m_RootPath+getListItem(m_FileLevelDirectories,index);
}

int CFileHasher::topLevelDirectoriesCount(void)
{
 return m_TopLevelDirectories.count();
}

QString CFileHasher::topLevelDirectory(const int index)
{
 return m_RootPath+getListItem(m_TopLevelDirectories,index);
}

int CFileHasher::savedFilesCount(void)
{
 return m_SavedFileNames.count();
}

QString CFileHasher::savedFileName(const int index)
{
 return getListItem(m_SavedFileNames,index);
}

QString CFileHasher::savedFileHash(const int index)
{
 return CByteArrayCodec::toString(m_SavedFileHashes.at(index),m_HashEncoding);
}

QString CFileHasher::savedFilePath(const int index)
{
 return m_RootPath+savedFileName(index);
}

int CFileHasher::missingFilesCount(void)
{
 return m_MissingFileIndices.count();
}

QString CFileHasher::missingFileName(const int index)
{
 return getListItem(m_SavedFileNames,m_MissingFileIndices.at(index));
}

QString CFileHasher::missingFileHash(const int index)
{
 return CByteArrayCodec::toString(m_SavedFileHashes.at(
         m_MissingFileIndices.at(index)),m_HashEncoding);
}

QString CFileHasher::missingFilePath(const int index)
{
 return m_RootPath+missingFileName(index);
}

int CFileHasher::selectedFilesCount(void)
{
 return m_SelectedFileNames.count();
}

QString CFileHasher::selectedFileName(const int index)
{
 return getListItem(m_SelectedFileNames,index);
}

QString CFileHasher::selectedFileHash(const int index)
{
 if (index < m_SelectedFileIndices.size())
 {
  return CByteArrayCodec::toString(m_SavedFileHashes.at(
          m_SelectedFileIndices.at(index)),m_HashEncoding);
 }
 else return "";
}

QString CFileHasher::selectedFilePath(const int index)
{
 return m_RootPath+selectedFileName(index);
}

int CFileHasher::sourceFilesCount(void)
{
 return m_SourceFileNames.count();
}

QString CFileHasher::sourceFileName(const int index)
{
 return getListItem(m_SourceFileNames,index);
}

QString CFileHasher::sourceFileHash(const int index)
{
 return CByteArrayCodec::toString(m_SourceFileHashes.at(index),m_HashEncoding);
}

QString CFileHasher::sourceFilePath(const int index)
{
 return m_RootPath+sourceFileName(index);
}

QString CFileHasher::calculatedFileHash(const int index)
{
 return CByteArrayCodec::toString(m_CalculatedFileHashes.at(index),m_HashEncoding);
}

CFileHasher::FileStatus CFileHasher::calculatedFileStatus(const int index)
{
 return m_FileStatuses.at(index);
}

int CFileHasher::targetFilesCount(void)
{
 return m_TargetFileNames.count();
}

QString CFileHasher::targetFileName(const int index)
{
 return getListItem(m_TargetFileNames,index);
}

QString CFileHasher::targetFileHash(const int index)
{
 return CByteArrayCodec::toString(m_TargetFileHashes.at(index),m_HashEncoding);
}

QString CFileHasher::targetFilePath(const int index)
{
 return m_RootPath+targetFileName(index);
}

bool CFileHasher::openChecksumFile(const QString& fileName, const int fileType)
{
 m_ChecksumFileName = fileName;
 QFile file(fileName);
 if (file.open(QIODevice::ReadOnly|QIODevice::Text))
 {
  m_ChecksumFile.clear();
  //
  QTextStream inputStream(&file);
  inputStream.setCodec(QTextCodec::codecForName(m_TextEncoding.toUtf8()));
  while (!inputStream.atEnd())
  {
   m_ChecksumFile << inputStream.readLine();
  }
  file.close();
  //
  if ((fileType<0)||(fileType>=CCryptographicHash::AlgorithmCount))
  {
   detectHashType();
  }
  else
  {
   setHashAlgorithm((CCryptographicHash::Algorithm)fileType);
  }
  if (CCryptographicHash::Crc32==fileType) parseSFVfile();
  else parseMD5file();
  //
  return true;
 }
 return false;
}

bool CFileHasher::reopenChecksumFile(void)
{
 return openChecksumFile(m_ChecksumFileName,m_HashAlgorithm);
}

bool CFileHasher::saveChecksumFile(const QString& fileName)
{
 QFile file(fileName);
 if (file.open(QIODevice::WriteOnly|QIODevice::Text))
 {
  QTextStream outputStream(&file);
  outputStream.setCodec(QTextCodec::codecForName(m_TextEncoding.toUtf8()));
  outputStream << m_ChecksumFile.join("\n");
  file.close();
  return true;
 }
 return false;
}

QString& CFileHasher::generateHtmlReport(void)
{
 m_Report.clear();
 //
 QString title,updating;
 switch (operationMode())
 {
  case Computation:
  {
   title = tr("QFileHasher report on computation of file hashes"); break;
  }
  case Verification:
  {
   title = tr("QFileHasher report on verification of file hashes"); break;
  }
  case Updating:
  {
   title = tr("QFileHasher report on updating checksum file");
   switch (updateMode())
   {
    case Brief:
    {
     updating = QString("<tr><td><h3><b>%1:</b></h3></td><td><h3> \"%2\" <i>(%3)</i></h3></td></tr>\n")
      .arg(tr("Selected updating mode"),tr("Brief"),
      tr("file hashes are recalculated only for already listed files"));
     break;
    }
    case Deep:
    {
     updating = QString("<tr><td><h3><b>%1:</b></h3></td><td><h3> \"%2\" <i>(%3)</i></h3></td></tr>\n")
      .arg(tr("Selected updating mode"),tr("Deep"),
      tr("file hashes are recalculated for all files found in listed directories"));
     break;
    }
    case Complete:
    {
     updating = QString("<tr><td><h3><b>%1:</b></h3></td><td><h3> \"%2\" <i>(%3)</i></h3></td></tr>\n")
      .arg(tr("Selected updating mode"),tr("Complete"),
      tr("file hashes are recalculated for all files found in listed directories"
         " and in all directories inside them"));
     break;
    }
    case DeltaDeep:
    {
     updating = QString("<tr><td><h3><b>%1:</b></h3></td><td><h3> \"%2\" <i>(%3)</i></h3></td></tr>\n")
      .arg(tr("Selected updating mode"),tr("delta-Deep"),
      tr("file hashes are recalculated for all files found in listed directories"
         ", excluding already listed files"));
     break;
    }
    case DeltaComplete:
    {
     updating = QString("<tr><td><h3><b>%1:</b></h3></td><td><h3> \"%2\" <i>(%3)</i></h3></td></tr>\n")
      .arg(tr("Selected updating mode"),tr("delta-Complete"),
      tr("file hashes are recalculated for all files found in listed directories"
         " and in all directories inside them, excluding already listed files"));
     break;
    }
   }
   break;
  }
 }
 //
 m_Report.append("<html>\n<head>\n<meta http-equiv=\"Content-Type\"content=\""
                 "text/html; charset=utf-8\">\n</head>\n<body>\n");
 m_Report.append(QString("<h1>%1</h1><hr>\n").arg(title));
 m_Report.append("<table>\n");
 if (CFileHasher::Updating==operationMode())
 {
  m_Report.append(updating);
 }
 m_Report.append(QString("<tr><td><h3><b>%1:</b></h3></td><td><h3>%2</h3></td></tr>\n")
  .arg(tr("Root path"),QString("%1").arg(m_RootPath)));
 m_Report.append(QString("<tr><td><h3><b>%1:</b></h3></td><td><h3>%2</h3></td></tr>\n")
  .arg(tr("Processed files"),QString("%1").arg(m_AllFiles.count())));
 m_Report.append(QString("<tr><td><h3><b>%1:</b></h3></td><td><h3>%2</h3></td></tr>\n")
  .arg(tr("Without errors"),QString("%1").arg(m_GoodFiles.count())));
 m_Report.append(QString("<tr><td><h3><b>%1:</b></h3></td><td><h3>%2</h3></td></tr>\n")
  .arg(tr("With any errors"),QString("%1").arg(m_BrokenFiles.count())));
 if (CFileHasher::Verification==operationMode())
 {
  m_Report.append(QString("<tr><td><h3><b>%1:</b></h3></td><td><h3>%2</h3></td></tr>\n")
   .arg(tr("Hash mismatch"),QString("%1").arg(m_HashMismatchFiles.count())));
 }
 m_Report.append(QString("<tr><td><h3><b>%1:</b></h3></td><td><h3>%2</h3></td></tr>\n")
  .arg(tr("Failed to access"),QString("%1").arg(m_NoAccessFiles.count())));
 m_Report.append("</table>\n<hr>\n");
 //
 QString hashName = CCryptographicHash::name(m_HashAlgorithm);
 QString hashEnc = CByteArrayCodec::name(m_HashEncoding);
 switch (operationMode())
 {
  case Computation:
  case Updating:
  {
   m_Report.append(QString("<table border=\"1\" cellpadding=\"4\">\n<tr><td><b>"
    "%1</b></td><td><b>%2</b></td><td><b>%3</b></td><td><b>%4</b></td></tr>\n")
    .arg(tr("Index"),tr("Status"),tr("%1 Hash (%2)").arg(hashName).arg(hashEnc),
     tr("File")));
   for (int i = 0; i < m_CalculatedFileHashes.count()/*sourceFilesCount()*/; i++)
   {
    m_Report.append(QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td></tr>\n")
     .arg(QString("%1").arg(i),statusName(calculatedFileStatus(i)),
     calculatedFileHash(i),sourceFilePath(i)));
   }
   break;
  }
  case Verification:
  {
   m_Report.append(QString("<table border=\"1\" cellpadding=\"4\">\n<tr><td><b>"
    "%1</b></td><td><b>%2</b></td><td><b>%3</b></td><td><b>%4</b></td><td><b>"
    "%5</b></td></tr>\n").arg(tr("Index"),tr("Status"),tr("%1 Hash (%2)")
    .arg(hashName).arg(hashEnc),tr("Saved %1 hash (%2)").arg(hashName).arg(hashEnc),
    tr("File")));
   for (int i = 0; i < m_CalculatedFileHashes.count()/*sourceFilesCount()*/; i++)
   {
    m_Report.append(QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td>"
     "<td>%5</td></tr>\n").arg(QString("%1").arg(i),statusName(calculatedFileStatus(i)),
     calculatedFileHash(i),sourceFileHash(i),sourceFilePath(i)));
   }
   break;
  }
 }
 m_Report.append("</table>\n</body>\n</html>\n");
 //
 return m_Report;
}

bool CFileHasher::saveHtmlReport(const QString& fileName)
{
 QFile file(fileName);
 if (file.open(QIODevice::WriteOnly|QIODevice::Text))
 {
  QTextStream outputStream(&file);
  outputStream.setCodec(QTextCodec::codecForName("UTF-8"));
  outputStream << m_Report;
  file.close();
  return true;
 }
 return false;
}

bool CFileHasher::saveFileList(const QString& fileName, const QStringList& list)
{
 QFile file(fileName);
 if (file.open(QIODevice::WriteOnly|QIODevice::Text))
 {
  QTextStream outputStream(&file);
  outputStream.setCodec(QTextCodec::codecForName(m_TextEncoding.toUtf8()));
  outputStream << list.join("\n");
  file.close();
  return true;
 }
 return false;
}

bool CFileHasher::detectHashType(void)
{
 for (int i = 0, ni = m_ChecksumFile.count(); i < ni; i++)
 {
  QString hashLine = m_ChecksumFile.at(i);
  if (hashLine.startsWith('#')||hashLine.startsWith(';'))
  {
   for (int j = 0; j < CCryptographicHash::AlgorithmCount; j++)
   {
    QString hashName = CCryptographicHash::name((CCryptographicHash::Algorithm)j);
    if (hashLine.indexOf(hashName) >= 0)
    {
     m_HashAlgorithm = (CCryptographicHash::Algorithm)j;
     return true;
 }}}}
 return false;
}

void CFileHasher::parseSFVfile(void)
{
 m_SavedFileNames.clear();
 m_SavedEncodedFileHashes.clear();
 //
 for (int i = 0, n = m_ChecksumFile.count(); i < n; i++)
 {
  QString line = m_ChecksumFile.at(i);
  if (!line.startsWith('#') && !line.startsWith(';') &&
      (line.size() > CCryptographicHash::minHashLength))
  {
   QString fileName, fileHash;
   int pos_spc = line.lastIndexOf(' ');
   if (pos_spc > 0)
   {
    fileName = line.left(pos_spc).trimmed();
    fileHash = line.right(line.size()-pos_spc-1).trimmed(); // DO NOT CHANGE CHARACTER CASE
   }
   if (!fileName.isEmpty() && !fileHash.isEmpty())
   {
    // ok, insert it in the list
    fileName = toNativeSeparators(fileName);
    m_SavedFileNames << fileName;
    m_SavedEncodedFileHashes << fileHash;
 }}}
 //
 decodeFileHashes();
}

void CFileHasher::parseMD5file(void)
{
 m_SavedFileNames.clear();
 m_SavedEncodedFileHashes.clear();
 //
 for (int i = 0, n = m_ChecksumFile.count(); i < n; i++)
 {
  QString line = m_ChecksumFile.at(i);
  if (!line.startsWith('#') && !line.startsWith(';') &&
      (line.size() > CCryptographicHash::minHashLength))
  {
   QString fileName, fileHash, hashName;
   int pos_spc = line.indexOf(' ');
   int pos_qmk = line.indexOf('?');
   int pos_ast = line.indexOf('*');
   if (pos_spc >= CCryptographicHash::minHashLength)
   {
    // line may be valid
    fileHash = line.left(pos_spc).trimmed(); // DO NOT CHANGE CHARACTER CASE
    if (pos_ast > pos_spc)
    {
     // filename beginning found
     fileName = line.right(line.size()-pos_ast-1).trimmed();
     if ((pos_qmk > pos_spc) && (pos_qmk < pos_ast))
     {
      // hash name found
      hashName = line.mid(pos_qmk+1,pos_ast-pos_qmk-1).toUpper();
    }}
    else
    {
     fileName = line.right(line.size()-pos_spc-1).trimmed();
   }}
   else
   {
    // error: line is invalid
    continue;
   }
   if (!fileName.isEmpty() && !fileHash.isEmpty())
   {
    // ok, insert it in the list
    fileName = toNativeSeparators(fileName);
    m_SavedFileNames << fileName;
    m_SavedEncodedFileHashes << fileHash;
   }
   if (!hashName.isEmpty())
   {
    CCryptographicHash::Algorithm hashAlgorithm = CCryptographicHash::algorithm(hashName);
    if (CCryptographicHash::AlgorithmCount != hashAlgorithm)
    {
     m_HashAlgorithm = hashAlgorithm;
    }
 }}}
 //
 decodeFileHashes();
}

void CFileHasher::decodeFileHashes(void)
{
 m_SavedFileHashes.clear();
 for (int i = 0; i < m_SavedEncodedFileHashes.size(); i++)
 {
  QString s = m_SavedEncodedFileHashes.at(i);
  QByteArray b = CByteArrayCodec::fromString(s,m_HashEncoding);
  m_SavedFileHashes.append(b);
 }
}

void CFileHasher::encodeFileHashes(void)
{
 m_TargetEncodedFileHashes.clear();
 for (int i = 0; i < m_TargetFileHashes.size(); i++)
 {
  QByteArray b = m_TargetFileHashes.at(i);
  QString s = CByteArrayCodec::toString(b,m_HashEncoding);
  m_TargetEncodedFileHashes.append(s);
 }
}

void CFileHasher::generateSFVfile(void)
{
 m_ChecksumFile.clear();
 // write header comment //
 QString hashName = CCryptographicHash::name(m_HashAlgorithm);
 if (m_DoWriteHeader)
 {
  //QString dateFormat = "dd.MM.yyyy hh:mm:ss";
  m_ChecksumFile << tr("; %1 file checksums generated by QFileHasher").arg(hashName);
  m_ChecksumFile << tr("; %1 (%2)").arg(QDateTime::currentDateTime()
                               .toString(m_DateTimeFormat),m_DateTimeFormat);
  m_ChecksumFile << ";";
 }
 // write file hash data //
 for (int i = 0, n = m_TargetEncodedFileHashes.count(); i < n; i++)
 {
  QString fileHash = m_TargetEncodedFileHashes.at(i);
  if (!fileHash.isEmpty())
  {
   QString fileName = m_TargetFileNames.at(i);
   QString fileLine = fileName+" "+fileHash;//.toUpper();
   m_ChecksumFile << fileLine;
 }}
}

void CFileHasher::generateMD5file(void)
{
 m_ChecksumFile.clear();
 // write header comment //
 QString hashName = CCryptographicHash::name(m_HashAlgorithm);
 if (m_DoWriteHeader)
 {
  //QString dateFormat = "dd.MM.yyyy hh:mm:ss";
  m_ChecksumFile << QString("%1 %2 file hashes generated by QFileHasher")
                .arg(m_CommentCharacter)
                .arg(hashName);
  m_ChecksumFile << QString("%1 %2 (%3)")
                .arg(m_CommentCharacter)
                .arg(QDateTime::currentDateTime().toString(m_DateTimeFormat))
                .arg(m_DateTimeFormat);
  m_ChecksumFile << "";
 }
 // write file hash data //
 for (int i = 0, n = m_TargetEncodedFileHashes.count(); i < n; i++)
 {
  QString fileHash = m_TargetEncodedFileHashes.at(i);
  /*if (CByteArrayCodec::Base16low != m_HashEncoding)
  {
   QByteArray b = CByteArrayCodec::fromString(fileHash,CByteArrayCodec::Base16low);
   fileHash = CByteArrayCodec::toString(b,m_HashEncoding);
  }*/
  if (!fileHash.isEmpty())
  {
   QString fileName = m_TargetFileNames.at(i);
   QString separator = " ";
   if (m_DoWriteHashAlgorithm) separator = " ?"+hashName+"*";
   else if (m_DoWriteAsteriskDelimiter) separator = " *";
   QString fileLine = fileHash+separator+fileName;
   m_ChecksumFile << fileLine;
 }}
}

void CFileHasher::generateChecksumFile(void)
{
 encodeFileHashes();
 if (CCryptographicHash::Crc32==m_HashAlgorithm) generateSFVfile();
 else generateMD5file();
}


void CFileHasher::scanDirectory(const QString& path, const bool recursively, QStringList& files)
{
 QDir dir(path);
 if (recursively)
 {
  QStringList entries = dir.entryList(QDir::Dirs|QDir::NoDotAndDotDot,QDir::Name);
  for (int i = 0, n = entries.count(); i < n; i++)
  {
   QString dirPath = dir.path()+QDir::separator()+entries[i];
   scanDirectory(dirPath,recursively,files);
 }}
 QStringList entries = dir.entryList(QDir::Files,QDir::Name);
 for (int i = 0, n = entries.count(); i < n; i++)
 {
  QString filePath = dir.path()+QDir::separator()+entries[i];
  filePath = toNativeSeparators(m_RootDir.relativeFilePath(filePath));
  files.append(filePath);
 }
}

void CFileHasher::selectDirectory(const QString& path, const bool recursively)
{
 scanDirectory(path,recursively,m_SelectedFileNames);
}

void CFileHasher::selectFile(const QString& path)
{
 QString filePath = toNativeSeparators(m_RootDir.relativeFilePath(path));
 m_SelectedFileNames.append(filePath);
}

void CFileHasher::removeDuplicatesFromSelection(void)
{
 removeDuplicates(m_SelectedFileNames);
}

void CFileHasher::deselectFile(const int index)
{
 m_SelectedFileNames.removeAt(index);
}

void CFileHasher::clearSelection(void)
{
 m_SelectedFileIndices.clear();
 m_SelectedFileNames.clear();
}


void CFileHasher::selectFromSavedFiles(QList<bool>& selection)
{
 clearSelection();
 for (int i = 0, n = selection.size(); i < n; i++)
 {
  if (selection.at(i))
  {
   m_SelectedFileIndices.append(i);
   m_SelectedFileNames.append(m_SavedFileNames.at(i));
 }}
}

void CFileHasher::selectFromSavedFiles(void)
{
 clearSelection();
 for (int i = 0, n = m_SavedFileNames.size(); i < n; i++)
 {
  m_SelectedFileIndices.append(i);
  m_SelectedFileNames.append(m_SavedFileNames.at(i));
 }
}


void CFileHasher::collectMissingAndExistingFiles(void)
{
 m_MissingFileIndices.clear();
 m_ExistingFileIndices.clear();
 //
 for (int i = 0; i < m_SelectedFileNames.size(); i++)
 {
  QString fileName = m_SelectedFileNames.at(i);
  if (QFile::exists(filePath(fileName)))
  {
   m_ExistingFileIndices.append(i);
  }
  else
  {
   m_MissingFileIndices.append(i);
 }}
}

void CFileHasher::collectFileLevelDirectories(void)
{
 m_FileLevelDirectories.clear();
 for (int i = 0, n = m_SavedFileNames.count(); i < n; i++)
 {
  QString fileName = m_SavedFileNames.at(i);
  QFileInfo fileInfo(fileName);
  m_FileLevelDirectories.append(toNativeSeparators(fileInfo.path()));
 }
 removeDuplicates(m_FileLevelDirectories);
}

void CFileHasher::collectTopLevelDirectories(void)
{
 m_TopLevelDirectories.clear();
 for (int i = 0, n = m_SavedFileNames.count(); i < n; i++)
 {
  QString fileName = m_SavedFileNames.at(i);
  QFileInfo fileInfo(fileName);
  QString filePath = toNativeSeparators(fileInfo.path());
  int from = 0;
  if (filePath.startsWith(QDir::separator())) from++;
  int pos = filePath.indexOf(QDir::separator(),from);
  if (pos > from)
  {
   fileName = filePath.left(pos);
  }
  else
  {
   fileName = filePath;
  }
  m_TopLevelDirectories.append(toNativeSeparators(fileName));
 }
 removeDuplicates(m_TopLevelDirectories);
}

void CFileHasher::findNewFiles(void)
{
 m_NewExistingFileNames.clear();
 for (int i = 0, n = m_FileLevelDirectories.size(); i < n; i++)
 {
  scanDirectory(filePath(m_FileLevelDirectories.at(i)),false,m_NewExistingFileNames);
 }
 if (m_DoUpdateRootDirectory)
 {
  scanDirectory(m_RootPath,false,m_NewExistingFileNames);
 }
}

void CFileHasher::findNewFilesAndDirectories(void)
{
 m_NewExistingFileNames.clear();
 if (m_DoUpdateRootDirectory)
 {
  scanDirectory(m_RootPath,true,m_NewExistingFileNames);
 }
 else
 {
  for (int i = 0, n = m_TopLevelDirectories.size(); i < n; i++)
  {
   scanDirectory(filePath(m_TopLevelDirectories.at(i)),true,m_NewExistingFileNames);
  }
 }
}

void CFileHasher::collectExclusivelyNewFiles(void)
{
 m_PreviouslyExistingFileIndices.clear();
 m_ExclusivelyNewFileIndices.clear();
 //
 for (int i = 0, n = m_NewExistingFileNames.size(); i < n; i++)
 {
  QString newFileName = m_NewExistingFileNames.at(i);
  bool fileIsExclusivelyNew = true;
  for (int j = 0, m = m_ExistingFileIndices.size(); j < m; j++)
  {
   int existingFileIndex = m_ExistingFileIndices.at(j);
   QString existingFileName = m_SavedFileNames.at(existingFileIndex);
   if (0 == QString::compare(newFileName,existingFileName))
   {
    m_PreviouslyExistingFileIndices.append(existingFileIndex);
    fileIsExclusivelyNew = false;
    break;
  }}
  if (fileIsExclusivelyNew)
  {
   m_ExclusivelyNewFileIndices.append(i);
 }}
}

void CFileHasher::beforeHashing(void)
{
 m_SourceFileNames.clear();
 m_SourceFileHashes.clear();
 //
 switch (m_OperationMode)
 {
  case Computation:
  {
   /*for (int i = 0; i < m_SelectedFileNames.size(); i++)
   {
    m_SourceFileNames.append(m_SelectedFileNames.at(i));
   }*/
   m_SourceFileNames.append(m_SelectedFileNames);
   break;
  }
  case Verification:
  {
   for (int i = 0; i < m_SelectedFileNames.size(); i++)
   {
    int index = m_SelectedFileIndices.at(i);
    m_SourceFileNames.append(m_SavedFileNames.at(index));
    m_SourceFileHashes.append(m_SavedFileHashes.at(index));
   }
   break;
  }
  case Updating:
  {
   switch (m_UpdateMode)
   {
    case Brief:
    {
     /*for (int i = 0; i < m_SelectedFileNames.size(); i++)
     {
      m_SourceFileNames.append(m_SelectedFileNames.at(i));
     }*/
     m_SourceFileNames.append(m_SelectedFileNames);
     break;
    }
    case Deep:
    case Complete:
    {
     /*for (int i = 0; i < m_NewExistingFileNames.size(); i++)
     {
      m_SourceFileNames.append(m_NewExistingFileNames.at(i));
     }*/
     m_SourceFileNames.append(m_NewExistingFileNames);
     break;
    }
    case DeltaDeep:
    case DeltaComplete:
    {
     for (int i = 0; i < m_ExclusivelyNewFileIndices.size(); i++)
     {
      int index = m_ExclusivelyNewFileIndices.at(i);
      m_SourceFileNames.append(m_NewExistingFileNames.at(index));
     }
     break;
   }}
   break;
 }}
 //
 m_CalculatedFileHashes.clear();
 m_FileStatuses.clear();
}

void CFileHasher::afterHashing(void)
{
 m_TargetFileNames.clear();
 m_TargetFileHashes.clear();
 //
 m_TargetFileNames.append(m_SourceFileNames);
 m_TargetFileHashes.append(m_CalculatedFileHashes);
 //
 switch (m_OperationMode)
 {
  case Computation:
  {
   break;
  }
  case Verification:
  {
   break;
  }
  case Updating:
  {
   switch (m_UpdateMode)
   {
    case Brief:
    {
     break;
    }
    case Deep:
    case Complete:
    {
     break;
    }
    case DeltaDeep:
    case DeltaComplete:
    {
     for (int i = 0; i < m_PreviouslyExistingFileIndices.size(); i++)
     {
      int index = m_PreviouslyExistingFileIndices.at(i);
      m_TargetFileNames.append(m_SavedFileNames.at(index));
      m_TargetFileHashes.append(m_SavedFileHashes.at(index));
     }
     break;
   }}
   if (m_DoKeepMissingFiles)
   {
    for (int i = 0; i < m_MissingFileIndices.size(); i++)
    {
     int index = m_MissingFileIndices.at(i);
     m_TargetFileNames.append(m_SavedFileNames.at(index));
     m_TargetFileHashes.append(m_SavedFileHashes.at(index));
    }
   }
   break;
 }}
 //
 encodeFileHashes();
}


void CFileHasher::resetCounters(void)
{
 m_UncheckedCount = sourceFilesCount();
 m_ProcessingCount = 0;
 m_GoodCount = 0;
 m_BrokenCount = 0;
}

void CFileHasher::clearFileLists(void)
{
 m_AllFiles.clear();
 m_GoodFileIndices.clear(); m_GoodFiles.clear();
 m_BrokenFileIndices.clear(); m_BrokenFiles.clear();
 m_HashMismatchFileIndices.clear(); m_HashMismatchFiles.clear();
 m_NoAccessFileIndices.clear(); m_NoAccessFiles.clear();
}

int CFileHasher::currentFileIndex(void)
{
 return m_CurrentFileIndex;
}

QString CFileHasher::currentFilePath(void)
{
 return m_HashingThread.filePath();
}

qint64 CFileHasher::currentFileSize(void)
{
 return m_HashingThread.fileSize();
}

CFileHasher::FileStatus CFileHasher::currentFileStatus(void)
{
 return m_CurrentFileStatus;
 //return m_HashingThread.status();
}

int CFileHasher::currentFileProgress(void)
{
 return m_HashingThread.progress();
}

int CFileHasher::totalFileProgress(void)
{
 if (sourceFilesCount() > 0)
 {
  return (int)(100.0*(m_CurrentFileIndex+1)/sourceFilesCount());
 }
 else return 0;
}


void CFileHasher::startHashing(void)
{
 m_CurrentFileIndex = 0;
 resetCounters();
 clearFileLists();
 m_HashingStopped = false;
 m_HashingThread.start(QThread::LowestPriority);
 if (m_HashingPaused) pauseHashing();
 else
 {
  emit startWorkerThread(sourceFilePath(m_CurrentFileIndex),m_HashAlgorithm);
 }
}

void CFileHasher::pauseHashing(void)
{
 if (m_HashingStopped) return;
 if (m_HashingPaused)
 {
  m_HashingPaused = false;
  m_HashingThread.resume();
  if (0 == m_ProcessingCount)
  {
   emit startWorkerThread(sourceFilePath(m_CurrentFileIndex),m_HashAlgorithm);
  }
 }
 else
 {
  m_HashingPaused = true;
  m_HashingThread.pause();
 }
}

void CFileHasher::stopHashing(void)
{
 //if (m_HashingPaused) pauseHashing();
 m_HashingPaused = false;
 m_HashingStopped = true;
 m_HashingThread.cancel();
 m_HashingThread.resume();
}

void CFileHasher::beginFileProcessing(const int index)
{
 emit startWorkerThread(filePath(m_SourceFileNames.at(index)),m_HashAlgorithm);
}

void CFileHasher::pauseFileProcessing(void)
{
 emit pauseWorkerThread();
}

void CFileHasher::resumeFileProcessing(void)
{
 emit resumeWorkerThread();
}

void CFileHasher::cancelFileProcessing(void)
{
 emit cancelWorkerThread();
}


void CFileHasher::workerThreadStarted(void)
{
 m_ProcessingCount = 1; //m_ProcessingCount++;
 emit fileProcessingBegan();
}

void CFileHasher::workerThreadUpdated(void)
{
 emit fileProcessingUpdated();
}

void CFileHasher::workerThreadFinished(void)
{
 if (m_HashingThread.status())
 {
  m_CurrentFileStatus = CFileHasher::Good;
 }
 else
 {
  m_CurrentFileStatus = NoAccess;
  m_NoAccessFileIndices.append(currentFileIndex());
  m_NoAccessFiles.append(currentFilePath());
 }
 m_AllFiles.append(currentFilePath());
 QByteArray fileHash;
 if (CFileHasher::Good == m_CurrentFileStatus)
 {
  fileHash = m_HashingThread.fileHash();
  //
  switch (m_OperationMode)
  {
   case CFileHasher::Computation:
   case CFileHasher::Updating:
   {
    m_UncheckedCount--; m_GoodCount++;
    m_GoodFileIndices.append(currentFileIndex());
    m_GoodFiles.append(currentFilePath());
    break;
   }
   case CFileHasher::Verification:
   {
    QByteArray savedHash = m_SourceFileHashes.at(m_CurrentFileIndex);
    if (savedHash == fileHash)
    {
     m_UncheckedCount--; m_GoodCount++;
     m_CurrentFileStatus = HashMatch;
     m_GoodFileIndices.append(currentFileIndex());
     m_GoodFiles.append(currentFilePath());
    }
    else
    {
     m_UncheckedCount--; m_BrokenCount++;
     m_CurrentFileStatus = HashMismatch;
     m_BrokenFileIndices.append(currentFileIndex());
     m_BrokenFiles.append(currentFilePath());
     m_HashMismatchFileIndices.append(currentFileIndex());
     m_HashMismatchFiles.append(currentFilePath());
    }
    break;
   }
  }
 }
 else
 {
  m_UncheckedCount--; m_BrokenCount++;
  m_BrokenFileIndices.append(currentFileIndex());
  m_BrokenFiles.append(currentFilePath());
 }
 //
 m_CalculatedFileHashes.append(fileHash);
 m_FileStatuses.append(currentFileStatus());
 //
 if (((m_CurrentFileIndex+1) < m_SourceFileNames.count()) && !m_HashingStopped)
 {
  emit fileProcessingFinished();
  m_ProcessingCount = 0; //m_ProcessingCount--;
  m_CurrentFileIndex++;
  if (!m_HashingPaused)
  {
   emit startWorkerThread(sourceFilePath(m_CurrentFileIndex),m_HashAlgorithm);
  }
 }
 else
 {
  stopHashing();
  m_ProcessingCount = 0;
  emit fileProcessingFinished();
 }
}

