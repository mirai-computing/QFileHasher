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

#ifndef FILEHASHER_H
#define FILEHASHER_H

#include <QObject>
#include <QtCore/QDir>
#include <QtCore/QStringList>

#include "filehashingthread.h"
#include "bytearraycodec.h"

class CFileHasher : public QObject
{
 Q_OBJECT
 public:
  enum OperationMode { Computation, Verification, Updating };
  enum UpdateMode { Brief, Deep, Complete, DeltaDeep, DeltaComplete };
  enum FileStatus { Good, NoAccess, HashMatch, HashMismatch };
 private:
  CFileHashingThread m_HashingThread;
  //
  /** \brief Operation mode: Computation, Verification or Updating. */
  CFileHasher::OperationMode m_OperationMode;
  /** \brief Updating mode: Brief, Deep, Complete, delta-Deep or delta-Complete. */
  CFileHasher::UpdateMode m_UpdateMode;
  //
  bool m_DoWriteHeader;
  bool m_DoWriteHashAlgorithm;
  bool m_DoWriteAsteriskDelimiter;
  QChar m_CommentCharacter;
  QString m_DateTimeFormat;
  bool m_DoKeepMissingFiles;
  bool m_DoUpdateRootDirectory;
  //
  QStringList m_TextEncodings;
  QString m_TextEncoding;
  QString m_ChecksumFileName;
  QStringList m_ChecksumFile;
  QStringList m_SavedFileNames;
  QStringList m_SavedEncodedFileHashes;
  QList<QByteArray> m_SavedFileHashes;
  QStringList m_SelectedFileNames;
  QList<int> m_SelectedFileIndices;
  QList<int> m_ExistingFileIndices;
  QList<int> m_MissingFileIndices;
  QStringList m_FileLevelDirectories;
  QStringList m_TopLevelDirectories;
  QStringList m_NewExistingFileNames;
  QList<int> m_ExclusivelyNewFileIndices;
  QList<int> m_PreviouslyExistingFileIndices;
  QStringList m_TargetFileNames;
  QStringList m_TargetEncodedFileHashes;
  QList<QByteArray> m_TargetFileHashes;
  QStringList m_SourceFileNames;
  QList<QByteArray> m_SourceFileHashes;
  QList<QByteArray> m_CalculatedFileHashes;
  QList<FileStatus> m_FileStatuses;
  QStringList m_AllFiles;
  QList<int> m_GoodFileIndices;
  QStringList m_GoodFiles;
  QList<int> m_BrokenFileIndices;
  QStringList m_BrokenFiles;
  QList<int> m_HashMismatchFileIndices;
  QStringList m_HashMismatchFiles;
  QList<int> m_NoAccessFileIndices;
  QStringList m_NoAccessFiles;
  QString m_Report;
  //
  //QStringList m_SavedFileNamesBackup;
  //QStringList m_SavedFileHashesBackup;
  //QStringList m_FileDirectories;
  /** \brief List of relative file paths to compute hashes. */
  //QStringList m_FileNames;
  /** \brief List of file hashes corresponding to m_FileNames items. */
  //QStringList m_FileHashes;
  /** \brief List of file names present in hashfile but actually missing. */
  //QStringList m_MissingFileNames;
  /** \brief List of file hashes corresponding to m_MissingFiles items. */
  //QStringList m_MissingFileHashes;
  /** \brief Selected hashing algorithm. */
  CCryptographicHash::Algorithm m_HashAlgorithm;
  /** \brief Selected hash representation. */
  CByteArrayCodec::Encoding m_HashEncoding;
  /** \brief Statring (root) directory path, should end with path separator. */
  QString m_RootPath;
  QDir m_RootDir;
  /** \brief Index of a file that is currently being processed. */
  int m_CurrentFileIndex;
  CFileHasher::FileStatus m_CurrentFileStatus;
  /** \brief Counter for unchecked file. */
  int m_UncheckedCount;
  /** \brief Counter for currently processing files, usually = 1 when working and = 0 when idle. */
  int m_ProcessingCount;
  /** \brief Counter for successfully processed files. */
  int m_GoodCount;
  /** \brief Counter for broken files. */
  int m_BrokenCount;
  /** \brief State flag to temporary halt file processing. */
  bool m_HashingPaused;
  /** \brief State flag to entirely stop file processing. */
  bool m_HashingStopped;
 private:
  QString toNativeSeparators(QString pathName);
  QString getListItem(QStringList& list, const int index);
 public:
  QString textEncoding(void) { return m_TextEncoding; }
  QString textEncoding(const int index) { return m_TextEncodings.at(index); }
  int textEncodingIndex(void) { return m_TextEncodings.indexOf(m_TextEncoding); }
  int testEncodingIndex(const QString& encoding) { return m_TextEncodings.indexOf(encoding); }
  int textEncodingCount(void) { return m_TextEncodings.size(); }
  bool& doWriteHeader(void) { return m_DoWriteHeader; }
  bool& doWriteHashAlgorithm(void) { return m_DoWriteHashAlgorithm; }
  bool& doWriteAsteriskDelimiter(void) { return m_DoWriteAsteriskDelimiter; }
  bool& doKeepMissingFiles(void) { return m_DoKeepMissingFiles; }
  bool& doUpdateRootDirectory(void) { return m_DoUpdateRootDirectory; }
  QChar& commentCharacter(void) { return m_CommentCharacter; }
  QString& dateTimeFormat(void) { return m_DateTimeFormat; }
  void setTextEncoding(const QString& encoding);
  CFileHasher::OperationMode operationMode(void);
  void setOperationMode(const CFileHasher::OperationMode mode);
  CFileHasher::UpdateMode updateMode(void);
  void setUpdateMode(const CFileHasher::UpdateMode mode);
  QString rootPath(void);
  void setRootPath(const QString& path);
  CCryptographicHash::Algorithm hashAlgorithm(void);
  void setHashAlgorithm(CCryptographicHash::Algorithm algorithm);
  CByteArrayCodec::Encoding hashEncoding(void);
  void setHashEncoding(CByteArrayCodec::Encoding encoding);
  QString statusName(const CFileHasher::FileStatus status);
  //
  QString filePath(const QString& fileName);
  int fileLevelDirectoriesCount(void);
  QString fileLevelDirectory(const int index);
  int topLevelDirectoriesCount(void);
  QString topLevelDirectory(const int index);
  int savedFilesCount(void);
  QString savedFileName(const int index);
  QString savedFileHash(const int index);
  QString savedFilePath(const int index);
  int missingFilesCount(void);
  QString missingFileName(const int index);
  QString missingFileHash(const int index);
  QString missingFilePath(const int index);
  int selectedFilesCount(void);
  QString selectedFileName(const int index);
  QString selectedFileHash(const int index);
  QString selectedFilePath(const int index);
  int sourceFilesCount(void);
  QString sourceFileName(const int index);
  QString sourceFileHash(const int index);
  QString sourceFilePath(const int index);
  QString calculatedFileHash(const int index);
  CFileHasher::FileStatus calculatedFileStatus(const int index);
  int targetFilesCount(void);
  QString targetFileName(const int index);
  QString targetFileHash(const int index);
  QString targetFilePath(const int index);
  // file i/o
  bool openChecksumFile(const QString& fileName, const int fileType);
  bool reopenChecksumFile(void);
  bool detectHashType(void);
  void parseSFVfile(void);
  void parseMD5file(void);
  void decodeFileHashes(void);
  void encodeFileHashes(void);
  void generateSFVfile(void);
  void generateMD5file(void);
  void generateChecksumFile(void);
  bool saveChecksumFile(const QString& fileName);
  QString& generateHtmlReport(void);
  QString& htmlReport(void) { return m_Report; }
  bool saveHtmlReport(const QString& fileName);
  QStringList& listAllFiles(void) { return m_AllFiles; }
  QStringList& listGoodFiles(void) { return m_GoodFiles; }
  QStringList& listBrokenFiles(void) { return m_BrokenFiles; }
  QStringList& listHashMismatchedFiles(void) { return m_HashMismatchFiles; }
  QStringList& listAccessFailedFiles(void) { return m_NoAccessFiles; }
  bool saveFileList(const QString& fileName, const QStringList& list);
  // calculation mode
  void scanDirectory(const QString& path, const bool recursively, QStringList& files);
  void selectDirectory(const QString& path, const bool recursively);
  void selectFile(const QString& path);
  void removeDuplicatesFromSelection(void);
  void deselectFile(const int index);
  void clearSelection(void);
  // verification mode
  void selectFromSavedFiles(QList<bool>& selection);
  void selectFromSavedFiles(void);
  // updating mode
  void collectMissingAndExistingFiles(void);
  void collectFileLevelDirectories(void);
  void collectTopLevelDirectories(void);
  void findNewFiles(void);
  void findNewFilesAndDirectories(void);
  void collectExclusivelyNewFiles(void);
  // all modes
  void beforeHashing(void);
  void afterHashing(void);
  //
  void resetCounters(void);
  void clearFileLists(void);
  int currentFileIndex(void);
  QString currentFilePath(void);
  qint64 currentFileSize(void);
  CFileHasher::FileStatus currentFileStatus(void);
  int currentFileProgress(void);
  int totalFileProgress(void);
  int uncheckedFileCount(void) { return m_UncheckedCount; }
  int processingFileCount(void) { return m_ProcessingCount; }
  int goodFileCount(void) { return m_GoodCount; }
  int brokenFileCount(void) { return m_BrokenCount; }
  //
  void startHashing(void);
  void pauseHashing(void);
  void stopHashing(void);
  bool hashingPaused(void) { return m_HashingPaused; }
  bool hashingStopped(void) { return m_HashingStopped; }
  //
  QStringList checksumFile(void) { return m_ChecksumFile; }
  // frontend interface //
 signals:
  void fileProcessingBegan(void);
  void fileProcessingUpdated(void);
  void fileProcessingFinished(void);
 public slots:
  void beginFileProcessing(const int index);
  void pauseFileProcessing(void);
  void resumeFileProcessing(void);
  void cancelFileProcessing(void);
  // backend interface //
 signals:
  void startWorkerThread(const QString& filePath,
                         const CCryptographicHash::Algorithm hashAlgorithm);
  void pauseWorkerThread(void);
  void resumeWorkerThread(void);
  void cancelWorkerThread(void);
 private slots:
  void workerThreadStarted(void);
  void workerThreadUpdated(void);
  void workerThreadFinished(void);
 public:
  CFileHasher();
};

#endif // FILEHASHER_H
