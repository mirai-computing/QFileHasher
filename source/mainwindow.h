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

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtCore/QSettings>
#include <QtGui/QDirModel>
#include <QtGui/QFileDialog>
#include <QtGui/QItemSelectionModel>
#include <QtGui/QListWidgetItem>
#include <QtGui/QMainWindow>
#include <QtGui/QTextDocument>
#include "feature.h"
#include "filehasher.h"
#include "bytearraycodec.h"
#include "multihash.h"

namespace Ui
{
 class MainWindow;
}

class MainWindow : public QMainWindow
{
 Q_OBJECT

public:
 MainWindow(QWidget *parent = 0);
 ~MainWindow();

private:
 Ui::MainWindow *ui;
 //
 /** \brief UI resource: icon for "unchecked" file status. */
 QIcon *m_IconUnchecked;
 /** \brief UI resource: icon for "processing" file status. */
 QIcon *m_IconProcessing;
 /** \brief UI resource: icon for "good" file status. */
 QIcon *m_IconGood;
 /** \brief UI resource: icon for "error" file status. */
 QIcon *m_IconError;
 /** \brief UI resource: "pause" icon for active file processing state. */
 QIcon *m_IconPause;
 /** \brief UI resource: "continue" icon for paused file processing state. */
 QIcon *m_IconContinue;
 /** \brief UI resource: "restart" icon for finished file processing state. */
 QIcon *m_IconRestart;
 //
 /** \brief A directory model to display directory tree and select root directory. */
 QDirModel *m_DirModel;
 /** \brief Selection model for choosing files. */
 QItemSelectionModel *m_SelectionModel;
 /** \brief File hasher logic implementation. */
 CFileHasher *m_FileHasher;
 //
 QFileDialog *m_OpenFileDialog;
 QFileDialog *m_SaveFileDialog;
 QStringList *m_FileFilters;
 QString m_ChecksumFileName;
 QSettings *m_Settings;
 QString m_ProcessingResultsHtml;
 //
 /** \brief Saves program settings (window geometry, paths) using QSettings. */
 void saveSettings(void);
 /** \brief Restores program settings (window geometry, paths) using QSettings. */
 void restoreSettings(void);
 /** \brief Processes command line parameters and applies options. */
 void processArguments(void);
 void setAccessible(QWidget& widget, const bool state);
 void setAccessible(QAction& action, const bool state);
 void setAccessible(QWidget* widget, const bool state) { setAccessible(*widget,state); }
 void setAccessible(QAction* action, const bool state) { setAccessible(*action,state); }
 void enable(QWidget& widget) { setAccessible(widget,true); }
 void disable(QWidget& widget) { setAccessible(widget,false); }
 void enable(QAction& action) { setAccessible(action,true); }
 void disable(QAction& action) { setAccessible(action,false); }
 void enable(QWidget* widget) { setAccessible(*widget,true); }
 void disable(QWidget* widget) { setAccessible(*widget,false); }
 void enable(QAction* action) { setAccessible(*action,true); }
 void disable(QAction* action) { setAccessible(*action,false); }
private slots:
 void switchToStartScreen(void);
 void switchToProcessStringScreen(void);
 void switchToProcessSingleFileScreen(void);
 void switchToProcessMultipleFilesScreen(void);
 void switchToDetectHashScreen(void);
 void switchToAboutScreen(void);
 void selectSingleFile(void);
 //
 void calculateStringOrFileHash(void);
 void verifyStringOrFileHash(void);
 //
 void setLocationComputer(void);
 void setLocationHome(void);
 void setLocationDocuments(void);
 void setLocationDesktop(void);
 void changeTextEncoding(const QString& encoding);
 void refreshDirTree(void);
 void changeRootDir(const QModelIndex& index);
 void selectRootDir(void);
 void switchToNewChecksumFileScreen(void);
 void openChecksumFile(void);
 void verifyFileHashes(void);
 void updateFileHashes(void);
 void refreshChecksumFile(void);
 void refreshChecksumFile1(int);
 void previewChecksumFile(void);
 void saveChecksumFile(void);
 void selectAllFiles(void);
 void showScanSelection(void);
 void selectFilesToScan(const bool recursively);
 void addFiles(void);
 void addRecursively(void);
 void addFile(const QModelIndex& index);
 void removeFile(QListWidgetItem * item);
 void clearList(void);
 void verifyItem(QListWidgetItem* item);
 void verifyAll(void);
 void verifyNone(void);
 void changeUpdateMode(const int index);
 void showCounters(void);
 void clearReport(void);
 void showReport(void);
 void clearFileLists(void);
 void showFileLists(void);
 void startHashing(void);
 void pauseHashing(void);
 void stopHashing(void);
 void beginFileProcessing(void);
 void updateFileProgress(void);
 void doneFileProcessing(void);
};

#endif // MAINWINDOW_H
