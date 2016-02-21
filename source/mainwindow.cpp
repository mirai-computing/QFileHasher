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
#include <sys/time.h>

#include <QtCore/QTextCodec>
#include <QtCore/QTextStream>
#include <QtGui/QDesktopServices>
#include <QtGui/QDesktopWidget>
#include <QtGui/QScrollBar>
#include <QtGui/QHeaderView>

#include "qt4helper.h"

#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
:QMainWindow(parent), ui(new Ui::MainWindow)
{
 ui->setupUi(this);
 // create resources //
 m_IconUnchecked = new QIcon(":/resources/images/status-unchecked-small.png");
 m_IconProcessing = new QIcon(":/resources/images/status-processing-small.png");
 m_IconGood = new QIcon(":/resources/images/status-good-small.png");
 m_IconError = new QIcon(":/resources/images/status-error-small.png");
 m_IconPause = new QIcon(":/resources/images/media-playback-pause.png");
 m_IconContinue = new QIcon(":/resources/images/media-playback-start.png");
 m_IconRestart = new QIcon(":/resources/images/action-restart.png");
 m_DirModel = new QDirModel(this);
 m_DirModel->setFilter(QDir::Dirs|QDir::NoDotAndDotDot);
 m_SelectionModel = new QItemSelectionModel(m_DirModel);
 m_FileHasher = new CFileHasher();
 m_FileFilters = new QStringList();
 /*(*m_FileFilters) << tr("MD4 hash files (*.md4)")
                  << tr("MD5 hash files (*.md5)")
                  << tr("SHA1 hash files (*.sha1)")
                  << tr("All files (*)");*/
 //
 {
  QComboBox *comboHashType[4] = {ui->comboBoxComputeHashType,
                                 ui->comboBoxVerifyHashType,
                                 ui->comboBoxUpdateHashType,
                                 ui->comboBoxStringHashType};
  for (int j = 0; j < 4; j++) comboHashType[j]->clear();
  for (int i = 0; i < CCryptographicHash::AlgorithmCount; i++)
  {
   QString hashName = CCryptographicHash::name((CCryptographicHash::Algorithm)i);
   QString hashDesc = CCryptographicHash::description((CCryptographicHash::Algorithm)i);
   QString hashExt = CCryptographicHash::extension((CCryptographicHash::Algorithm)i);
   for (int j = 0; j < 4; j++) comboHashType[j]->addItem(hashName);
   (*m_FileFilters) << tr("%1 hash files (*.%2)").arg(hashDesc).arg(hashExt);
  }
  (*m_FileFilters) << tr("All files (*)");
 }
 //
 m_OpenFileDialog = new QFileDialog(this,Qt::Dialog);
 m_OpenFileDialog->setAcceptMode(QFileDialog::AcceptOpen);
 m_OpenFileDialog->setFileMode(QFileDialog::ExistingFile);
 m_OpenFileDialog->setFilters(*m_FileFilters);
 m_SaveFileDialog = new QFileDialog(this,Qt::Dialog);
 m_SaveFileDialog->setAcceptMode(QFileDialog::AcceptSave);
 m_SaveFileDialog->setFilters(*m_FileFilters);
 m_Settings = new QSettings("MiraiComputing","QFileHasher");
 // configure //
 // setup ui //
 ui->treeViewDirs->setModel(m_DirModel);
 ui->treeViewDirs->hideColumn(1);
 ui->treeViewDirs->hideColumn(2);
 ui->treeViewDirs->hideColumn(3);
 ui->treeViewDirs->header()->setResizeMode(QHeaderView::ResizeToContents);
 ui->listViewComputeSelectionSource->setModel(m_DirModel);
 ui->listViewComputeSelectionSource->setSelectionModel(m_SelectionModel);
 ui->listViewComputeSelectionSource->setSelectionMode(QAbstractItemView::ExtendedSelection);
 {
  //int h = QFontMetrics(ui->treeViewDirs->font()).height();
  //ui->tableWidget->verticalHeader()->setDefaultSectionSize(h*2);
  int h = ui->tableWidget->horizontalHeader()->height();
  ui->tableWidget->verticalHeader()->setDefaultSectionSize(h);
 }
 //ui->tableWidget
 //ui->tableWidget->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
 ui->labelFileName->setText(""); ui->labelFileSize->setText("");
 {
  QComboBox *comboTextEncoding[3] = {ui->comboBoxEncoding,
                                     ui->comboBoxFileListEncoding,
                                     ui->comboBoxStringTextEncoding};
  for (int j = 0; j < 3; j++) comboTextEncoding[j]->clear();
  for (int i = 0, n = m_FileHasher->textEncodingCount(); i < n; i++)
  {
   QString encoding = m_FileHasher->textEncoding(i);
   for (int j = 0; j < 3; j++) comboTextEncoding[j]->addItem(encoding);
  }
  int index = m_FileHasher->textEncodingIndex();
  for (int j = 0; j < 3; j++) comboTextEncoding[j]->setCurrentIndex(index);
 }
 {
  QComboBox *comboHashEncoding[2] = {ui->comboBoxHashEncoding,
                                     ui->comboBoxStringHashEncoding};
  for (int j = 0; j < 2; j++)
  {
   comboHashEncoding[j]->clear();
   comboHashEncoding[j]->addItem(tr("Base16 upper case"));
   comboHashEncoding[j]->addItem(tr("Base16 lower case"));
   comboHashEncoding[j]->addItem(tr("Base32"));
   comboHashEncoding[j]->addItem(tr("Base32hex"));
   comboHashEncoding[j]->addItem(tr("Base64"));
   comboHashEncoding[j]->addItem(tr("Base64url"));
  }
 }
 // connect signals to slots //
 connect(ui->action_New,SIGNAL(triggered()),this,SLOT(switchToNewChecksumFileScreen()));
 connect(ui->action_Open,SIGNAL(triggered()),this,SLOT(openChecksumFile()));
 connect(ui->action_Verify,SIGNAL(triggered()),this,SLOT(verifyFileHashes()));
 connect(ui->action_Update,SIGNAL(triggered()),this,SLOT(updateFileHashes()));
 connect(ui->action_Preview,SIGNAL(triggered()),this,SLOT(previewChecksumFile()));
 connect(ui->action_Save,SIGNAL(triggered()),this,SLOT(saveChecksumFile()));
 connect(ui->action_About,SIGNAL(triggered()),this,SLOT(switchToAboutScreen()));
 connect(ui->pushButtonLocationComputer,SIGNAL(clicked()),
         this,SLOT(setLocationComputer()));
 connect(ui->pushButtonLocationHome,SIGNAL(clicked()),
         this,SLOT(setLocationHome()));
 connect(ui->pushButtonLocationDocuments,SIGNAL(clicked()),
         this,SLOT(setLocationDocuments()));
 connect(ui->pushButtonLocationDesktop,SIGNAL(clicked()),
         this,SLOT(setLocationDesktop()));
 connect(ui->pushButtonRefreshDirTree,SIGNAL(clicked()),
         this,SLOT(refreshDirTree()));
 connect(ui->pushButtonRefreshDirTree2,SIGNAL(clicked()),
         this,SLOT(refreshDirTree()));
 connect(ui->treeViewDirs,SIGNAL(clicked(QModelIndex)),
         this,SLOT(changeRootDir(QModelIndex)));
 connect(ui->pushButtonSelectRoot,SIGNAL(clicked()),
         this,SLOT(selectRootDir()));
 connect(ui->pushButtonSelectAll,SIGNAL(clicked()),
         this,SLOT(selectAllFiles()));
 connect(ui->pushButtonAddFiles,SIGNAL(clicked()),
         this,SLOT(addFiles()));
 connect(ui->pushButtonAddRecursively,SIGNAL(clicked()),
         this,SLOT(addRecursively()));
 connect(ui->listViewComputeSelectionSource,SIGNAL(doubleClicked(QModelIndex)),
         this,SLOT(addFile(QModelIndex)));
 connect(ui->listWidgetComputeSelection,SIGNAL(itemDoubleClicked(QListWidgetItem*)),
         this,SLOT(removeFile(QListWidgetItem*)));
 connect(ui->pushButtonClearList,SIGNAL(clicked()),
         this,SLOT(clearList()));
 connect(ui->pushButtonStartHashing,SIGNAL(clicked()),
         this,SLOT(startHashing()));
 connect(ui->pushButtonCancelHashing,SIGNAL(clicked()),
         this,SLOT(switchToNewChecksumFileScreen()));
 connect(ui->pushButtonPauseHashing,SIGNAL(clicked()),
         this,SLOT(pauseHashing()));
 connect(ui->pushButtonStopHashing,SIGNAL(clicked()),
         this,SLOT(stopHashing()));
 connect(ui->pushButtonVerifyAll,SIGNAL(clicked()),
         this,SLOT(verifyAll()));
 connect(ui->pushButtonVerifyNone,SIGNAL(clicked()),
         this,SLOT(verifyNone()));
 connect(ui->listWidgetSelection,SIGNAL(itemClicked(QListWidgetItem*)),
         this,SLOT(verifyItem(QListWidgetItem*)));
 connect(ui->pushButtonStartVerification,SIGNAL(clicked()),
         this,SLOT(startHashing()));
 connect(ui->pushButtonCancelVerification,SIGNAL(clicked()),
         this,SLOT(switchToNewChecksumFileScreen()));
 connect(ui->comboBoxUpdateMode,SIGNAL(currentIndexChanged(int)),
         this,SLOT(changeUpdateMode(int)));
 connect(ui->pushButtonStartUpdating,SIGNAL(clicked()),
         this,SLOT(startHashing()));
 connect(ui->pushButtonCancelUpdating,SIGNAL(clicked()),
         this,SLOT(switchToNewChecksumFileScreen()));
 connect(ui->comboBoxEncoding,SIGNAL(currentIndexChanged(QString)),
         this,SLOT(changeTextEncoding(QString)));
 connect(ui->comboBoxFileListEncoding,SIGNAL(currentIndexChanged(int)),
         ui->comboBoxEncoding,SLOT(setCurrentIndex(int)));
 connect(ui->comboBoxEncoding,SIGNAL(currentIndexChanged(int)),
         ui->comboBoxFileListEncoding,SLOT(setCurrentIndex(int)));
 //
 connect(m_FileHasher,SIGNAL(fileProcessingBegan()),
         this,SLOT(beginFileProcessing()));
 connect(m_FileHasher,SIGNAL(fileProcessingUpdated()),
         this,SLOT(updateFileProgress()));
 connect(m_FileHasher,SIGNAL(fileProcessingFinished()),
         this,SLOT(doneFileProcessing()));
 //
 connect(ui->checkBoxWriteHeader,SIGNAL(clicked()),
         this,SLOT(refreshChecksumFile()));
 connect(ui->checkBoxWriteHashAlgorithm,SIGNAL(clicked()),
         this,SLOT(refreshChecksumFile()));
 connect(ui->checkBoxWriteAsteriskDelimiter,SIGNAL(clicked()),
         this,SLOT(refreshChecksumFile()));
 connect(ui->comboBoxHashEncoding,SIGNAL(currentIndexChanged(int)),
         this,SLOT(refreshChecksumFile1(int)));
 connect(ui->comboBoxCommentCharacter,SIGNAL(currentIndexChanged(int)),
         this,SLOT(refreshChecksumFile1(int)));
 connect(ui->comboBoxDateTimeFormat,SIGNAL(currentIndexChanged(int)),
         this,SLOT(refreshChecksumFile1(int)));
 // start screen
 connect(ui->action_StartScreen,SIGNAL(triggered()),
         this,SLOT(switchToStartScreen()));
 connect(ui->pushButtonProcessString,SIGNAL(clicked()),
         this,SLOT(switchToProcessStringScreen()));
 connect(ui->pushButtonProcessFile,SIGNAL(clicked()),
         this,SLOT(switchToProcessSingleFileScreen()));
 connect(ui->pushButtonDetectHash,SIGNAL(clicked()),
         this,SLOT(switchToDetectHashScreen()));
 connect(ui->pushButtonProcessFiles,SIGNAL(clicked()),
         this,SLOT(switchToProcessMultipleFilesScreen()));
 // string or single file hashing
 connect(ui->pushButtonSelectFile,SIGNAL(clicked()),
         this,SLOT(selectSingleFile()));
 connect(ui->pushButtonCalculateStringHash,SIGNAL(clicked()),
         this,SLOT(calculateStringOrFileHash()));
 connect(ui->pushButtonVerifyStringHash,SIGNAL(clicked()),
         this,SLOT(verifyStringOrFileHash()));
 // switch to initial state //
 ui->radioButtonAbsolutePaths->hide();
 ui->radioButtonRelativePaths->hide();
 {
  //QString path = QDesktopServices::storageLocation(QDesktopServices::HomeLocation);
  QString path = QDir::rootPath();
  m_FileHasher->setRootPath(path);
 }
 //ui->treeViewDirs->setCurrentIndex(m_DirModel->index(m_FileHasher->getRootPath()));
 restoreSettings();
 //switchToNewChecksumFileScreen();
 switchToStartScreen();
 processArguments();
 //
}

MainWindow::~MainWindow()
{
 saveSettings(); m_Settings->sync(); delete m_Settings;
 //
 delete m_SaveFileDialog; delete m_OpenFileDialog;
 delete m_FileFilters; delete m_SelectionModel; delete m_DirModel;
 delete m_IconUnchecked; delete m_IconProcessing; delete m_IconGood;
 delete m_IconError; delete m_IconPause; delete m_IconContinue;
 //
 delete m_FileHasher;
 //
 delete ui;
}

void MainWindow::saveSettings(void)
{
 m_Settings->setValue("core.firstlaunch",false);
 m_Settings->setValue("core.rootpath",m_FileHasher->rootPath());
 m_Settings->setValue("core.encoding",m_FileHasher->textEncoding());
 m_Settings->setValue("core.algorithm",m_FileHasher->hashAlgorithm());
 //
 m_Settings->setValue("core.md5format.header",m_FileHasher->doWriteHeader());
 m_Settings->setValue("core.md5format.comment",m_FileHasher->commentCharacter());
 m_Settings->setValue("core.md5format.datetime",m_FileHasher->dateTimeFormat());
 m_Settings->setValue("core.md5format.hashalgorithm",m_FileHasher->doWriteHashAlgorithm());
 m_Settings->setValue("core.md5format.asterisk",m_FileHasher->doWriteAsteriskDelimiter());
 m_Settings->setValue("core.md5format.hashencoding",m_FileHasher->hashEncoding());
 //
 m_Settings->setValue("ui.mainwindow.pos.x",this->pos().x());
 m_Settings->setValue("ui.mainwindow.pos.y",this->pos().y());
 m_Settings->setValue("ui.mainwindow.width",this->width());
 m_Settings->setValue("ui.mainwindow.height",this->height());
}

void MainWindow::restoreSettings(void)
{
 bool firstLaunch = m_Settings->value("core.firstlaunch",true).toBool();
 m_FileHasher->setRootPath(m_Settings->value("core.rootpath",QDir::rootPath()).toString());
 m_FileHasher->setTextEncoding(m_Settings->value("core.encoding",m_FileHasher->textEncoding()).toString());
 m_FileHasher->setHashAlgorithm((CCryptographicHash::Algorithm)
  m_Settings->value("core.algorithm",m_FileHasher->hashAlgorithm()).toInt());
 // read core settings
 m_FileHasher->doWriteHeader() =
  m_Settings->value("core.md5format.header",m_FileHasher->doWriteHeader()).toBool();
 m_FileHasher->commentCharacter() =
  m_Settings->value("core.md5format.comment",m_FileHasher->commentCharacter()).toChar();
 m_FileHasher->dateTimeFormat() =
  m_Settings->value("core.md5format.datetime",m_FileHasher->dateTimeFormat()).toString();
 m_FileHasher->doWriteHashAlgorithm() =
  m_Settings->value("core.md5format.hashalgorithm",m_FileHasher->doWriteHashAlgorithm()).toBool();
 m_FileHasher->doWriteAsteriskDelimiter() =
  m_Settings->value("core.md5format.asterisk",m_FileHasher->doWriteAsteriskDelimiter()).toBool();
 m_FileHasher->setHashEncoding((CByteArrayCodec::Encoding)
  m_Settings->value("core.md5format.hashencoding",m_FileHasher->hashEncoding()).toInt());
 // reflect changes in ui
 ui->treeViewDirs->setCurrentIndex(m_DirModel->index(m_FileHasher->rootPath()));
 ui->comboBoxEncoding->setCurrentIndex(ui->comboBoxEncoding->findText(
  m_FileHasher->textEncoding()));
 ui->comboBoxComputeHashType->setCurrentIndex(m_FileHasher->hashAlgorithm());
 ui->comboBoxUpdateHashType->setCurrentIndex(m_FileHasher->hashAlgorithm());
 ui->comboBoxVerifyHashType->setCurrentIndex(m_FileHasher->hashAlgorithm());
 //
 if (firstLaunch)
 {
  int x = (QApplication::desktop()->width() - this->width()) / 2;
  int y = (QApplication::desktop()->height() - this->height()) / 2;
  this->setGeometry(x,y,this->width(),this->height());
 }
 else
 {
  int x = m_Settings->value("ui.mainwindow.pos.x",this->pos().x()).toInt();
  int y = m_Settings->value("ui.mainwindow.pos.y",this->pos().y()).toInt();
  int w = m_Settings->value("ui.mainwindow.width",this->width()).toInt();
  int h = m_Settings->value("ui.mainwindow.height",this->height()).toInt();
  //this->setGeometry(x,y,w,h); // this won't work against window decorators
  this->resize(QSize(w,h));
  this->move(QPoint(x,y));
 }
}

void MainWindow::processArguments(void)
{
 QStringList arguments = QApplication::arguments();
 if (arguments.size() > 1)
 {
  m_OpenFileDialog->selectFile(arguments.at(1));
  openChecksumFile();
 }
}

void MainWindow::switchToStartScreen(void)
{
 disable(ui->action_StartScreen);
 disable(ui->action_New); disable(ui->action_Open);
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_Save);
 ui->stackedWidget->setCurrentWidget(ui->pageStartScreen);
 ui->statusBar->showMessage("");
}

void MainWindow::switchToProcessStringScreen(void)
{
 ui->checkBoxUseFileContents->setChecked(false);
 //if (ui->lineEditStringFilename->text().isEmpty())
 {
  ui->lineEditStringFilename->setText(tr("Write your string here."));
 }
 enable(ui->action_StartScreen);
 disable(ui->action_New); disable(ui->action_Open);
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_Save);
 ui->labelStringTextEncoding->setVisible(true);
 ui->comboBoxStringTextEncoding->setVisible(true);
 ui->checkBoxUseFileContents->setVisible(false);
 ui->checkBoxUseFileContents->setChecked(false);
 ui->pushButtonSelectFile->setVisible(false);
 ui->pushButtonCalculateStringHash->setVisible(true);
 ui->pushButtonVerifyStringHash->setVisible(true);
 ui->pushButtonDetectStringHash->setVisible(false);
 ui->tableWidgetStringHash->setVisible(false);
 ui->lineEditStringHash->clear();
 ui->stackedWidget->setCurrentWidget(ui->pageStringHash);
}


void MainWindow::switchToProcessSingleFileScreen(void)
{
 ui->checkBoxUseFileContents->setChecked(false);
 //if (ui->lineEditStringFilename->text().isEmpty())
 {
  ui->lineEditStringFilename->setText(tr("Write your filename here or press \"Select file\" button."));
 }
 enable(ui->action_StartScreen);
 disable(ui->action_New); disable(ui->action_Open);
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_Save);
 ui->labelStringTextEncoding->setVisible(false);
 ui->comboBoxStringTextEncoding->setVisible(false);
 ui->checkBoxUseFileContents->setVisible(true);
 ui->checkBoxUseFileContents->setChecked(true);
 ui->pushButtonSelectFile->setVisible(true);
 ui->pushButtonCalculateStringHash->setVisible(true);
 ui->pushButtonVerifyStringHash->setVisible(true);
 ui->pushButtonDetectStringHash->setVisible(false);
 ui->tableWidgetStringHash->setVisible(false);
 ui->lineEditStringHash->clear();
 ui->stackedWidget->setCurrentWidget(ui->pageStringHash);
}

void MainWindow::switchToProcessMultipleFilesScreen(void)
{
 switchToNewChecksumFileScreen();
}

void MainWindow::switchToDetectHashScreen(void)
{
 enable(ui->action_StartScreen);
 disable(ui->action_New); disable(ui->action_Open);
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_Save);
 ui->labelStringTextEncoding->setVisible(true);
 ui->comboBoxStringTextEncoding->setVisible(true);
 ui->checkBoxUseFileContents->setVisible(true);
 ui->checkBoxUseFileContents->setChecked(false);
 ui->pushButtonSelectFile->setVisible(true);
 ui->pushButtonCalculateStringHash->setVisible(false);
 ui->pushButtonVerifyStringHash->setVisible(false);
 ui->pushButtonDetectStringHash->setVisible(true);
 ui->tableWidgetStringHash->setVisible(false);
 //if (ui->lineEditStringHash->text().isEmpty())
 {
  ui->lineEditStringFilename->setText(tr("Write your string or filename here or press \"Select file\" button."));
  ui->lineEditStringHash->setText(tr("Write your hash here."));
 }
 ui->stackedWidget->setCurrentWidget(ui->pageStringHash);
}

void MainWindow::switchToAboutScreen(void)
{
 enable(ui->action_StartScreen);
 ui->stackedWidget->setCurrentWidget(ui->pageAbout);
 //enable(ui->action_New);
 ui->statusBar->showMessage(tr("Click \"Begin\" button to go back to work."));
}

void MainWindow::selectSingleFile(void)
{
 QStringList file_filter;
 file_filter << tr("All files (*)");
 QFileDialog dialog;
 dialog.setAcceptMode(QFileDialog::AcceptOpen);
 dialog.setFileMode(QFileDialog::ExistingFile);
 dialog.setFilters(file_filter);
 if (QFileDialog::Accepted == dialog.exec())
 {
  ui->lineEditStringFilename->setText(dialog.selectedFiles().first());
  ui->checkBoxUseFileContents->setChecked(true);
 }
}

void MainWindow::calculateStringOrFileHash(void)
{
 // initialize multihash
 CCryptographicMultiHash multi_hash;
 int hash_type = ui->comboBoxStringHashType->currentIndex();
 if (ui->checkBoxShowAllStringHashes->isChecked())
 {
  multi_hash.enableAllMethods();
  ui->tableWidgetStringHash->setVisible(true);
 }
 else
 {
  multi_hash.disableAllMethods();
  multi_hash.enableMethod((CCryptographicMultiHash::Algorithm)hash_type);
  ui->tableWidgetStringHash->setVisible(false);
 }
 // feed data to multihash
 if (ui->checkBoxUseFileContents->isChecked())
 {
  // calculate single file hash
  QFile file(ui->lineEditStringFilename->text());
  if (file.open(QIODevice::ReadOnly))
  {
   while (file.pos() < file.size())
   {
    QApplication::processEvents();
    //CSleeper::msleep(100);
    multi_hash.addData(file.read(0x100000));
    int file_progress = (int)(100.0*file.pos()/file.size());
    ui->statusBar->showMessage(tr("File hashing in progress ... %1\% done.")
                               .arg(file_progress));
   }
   file.close();
   ui->statusBar->showMessage(tr("File hashing finished."));
  }
  else
  {
   ui->statusBar->showMessage(tr("Error: Cannot open file."));
   return;
  }
 }
 else
 {
  // calculate string hash
  QString text_codec_name = ui->comboBoxStringTextEncoding->currentText();
  QTextCodec *text_codec = QTextCodec::codecForName(text_codec_name.toUtf8());
  if (0!=text_codec)
  {
   QString text = ui->lineEditStringFilename->text();
   QByteArray data = text_codec->fromUnicode(text);
   multi_hash.addData(data);
  }
  else
  {
   ui->statusBar->showMessage(tr("Error: Unsupported text encoding \"%1\".")
                              .arg(text_codec_name));
   return;
  }
 }
 // show results
 QByteArray hash_data = multi_hash.result((CCryptographicMultiHash::Algorithm)hash_type);
 int hash_encoding = ui->comboBoxStringHashEncoding->currentIndex();
 QString hash_text = CByteArrayCodec::toString(hash_data,(CByteArrayCodec::Encoding)hash_encoding);
 ui->lineEditStringHash->setText(hash_text);
 if (ui->checkBoxShowAllStringHashes->isChecked())
 {
  //QList<CCryptographicMultiHash::Algorithm> methods; QStringList method_names;
  //QList<QByteArray> mhash_data = multi_hash.messageDigests(methods,method_names);
  //
  QTableWidget *tw = ui->tableWidgetStringHash;
  tw->clear();
  tw->setRowCount(0);
  tw->setColumnCount(3);
  tw->setRowCount(m_FileHasher->sourceFilesCount());
  tw->horizontalHeader()->setResizeMode(0,QHeaderView::ResizeToContents);
  tw->horizontalHeader()->setResizeMode(1,QHeaderView::ResizeToContents);
  tw->horizontalHeader()->setResizeMode(2,QHeaderView::Stretch);
  tw->setHorizontalHeaderItem(0,new QTableWidgetItem(tr("Hash type")));
  tw->setHorizontalHeaderItem(1,new QTableWidgetItem(tr("Hash encoding")));
  tw->setHorizontalHeaderItem(2,new QTableWidgetItem(tr("Hash value")));
  int n = (int)CCryptographicMultiHash::AlgorithmCount;
  int m = (int)CByteArrayCodec::EncodingCount;
  tw->setRowCount(n*m);
  for (int i = 0, k = 0; i < n; i++)
  {
   QString hash_name = CCryptographicMultiHash::name((CCryptographicMultiHash::Algorithm)i);
   QByteArray hash_data = multi_hash.result((CCryptographicMultiHash::Algorithm)i);
   for (int j = 0; j < m; j++, k++)
   {
    QString hash_encoding_name = CByteArrayCodec::name((CByteArrayCodec::Encoding)j);
    QString hash_text = CByteArrayCodec::toString(hash_data,((CByteArrayCodec::Encoding)j));
    tw->setItem(k,0,new QTableWidgetItem(hash_name));
    tw->setItem(k,1,new QTableWidgetItem(hash_encoding_name));
    tw->setItem(k,2,new QTableWidgetItem(hash_text));
   }
  }
  tw->resizeColumnsToContents();
  tw->resizeRowsToContents();
 }
}

void MainWindow::verifyStringOrFileHash(void)
{
 // backup input
 QString user_hash_text = ui->lineEditStringHash->text();
 calculateStringOrFileHash();
 QString hash_text = ui->lineEditStringHash->text();
 if (ui->checkBoxUseFileContents->isChecked())
 {
  // verify single file hash
  if (hash_text == user_hash_text)
  {
   ui->statusBar->showMessage(tr("File hash is correct!"));
  }
  else
  {
   ui->statusBar->showMessage(tr("File hash is incorrect."));
  }
 }
 else
 {
  // verify string hash
  if (hash_text == user_hash_text)
  {
   ui->statusBar->showMessage(tr("String hash is correct!"));
  }
  else
  {
   ui->statusBar->showMessage(tr("String hash is incorrect."));
  }
 }
 // restore input
 ui->lineEditStringHash->setText(user_hash_text);
}

void MainWindow::setAccessible(QWidget& widget, const bool state)
{
 widget.setEnabled(state);
 //widget.setVisible(state);
}

void MainWindow::setAccessible(QAction& action, const bool state)
{
 if (action.isEnabled()==state) return;
 action.setEnabled(state);
 //action.setVisible(state);
 if (state)
 {
  QString text = action.data().toString();
  if (!text.isEmpty()) action.setText(text);
 }
 else
 {
  action.setData(action.text());
  action.setText("");
 }
}

void MainWindow::setLocationComputer(void)
{
 QString path = QDir::rootPath();
 changeRootDir(m_DirModel->index(path));
}

void MainWindow::setLocationHome(void)
{
 QString path = QDesktopServices::storageLocation(QDesktopServices::HomeLocation);
 changeRootDir(m_DirModel->index(path));
}

void MainWindow::setLocationDocuments(void)
{
 QString path = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
 changeRootDir(m_DirModel->index(path));
}

void MainWindow::setLocationDesktop(void)
{
 QString path = QDesktopServices::storageLocation(QDesktopServices::DesktopLocation);
 changeRootDir(m_DirModel->index(path));
}

void MainWindow::changeTextEncoding(const QString& encoding)
{
 m_FileHasher->setTextEncoding(encoding);
 switch (m_FileHasher->operationMode())
 {
  case CFileHasher::Verification:
  {
   m_FileHasher->reopenChecksumFile();
   int v = ui->textEditChecksumFile->verticalScrollBar()->value();
   int h = ui->textEditChecksumFile->horizontalScrollBar()->value();
   ui->textEditChecksumFile->setPlainText(m_FileHasher->checksumFile().join("\n"));
   ui->textEditChecksumFile->verticalScrollBar()->setValue(v);
   ui->textEditChecksumFile->horizontalScrollBar()->setValue(h);
   break;
  }
 }
}

void MainWindow::refreshDirTree(void)
{
 m_DirModel->refresh();
}

void MainWindow::changeRootDir(const QModelIndex& index)
{
 m_FileHasher->setRootPath(m_DirModel->filePath(index));
 QString rootPath = m_FileHasher->rootPath();
 setAccessible(ui->pushButtonSelectRoot,!rootPath.isEmpty());
 ui->lineEditRootDir->setText(rootPath);
 ui->treeViewDirs->setCurrentIndex(index);
}

void MainWindow::selectRootDir(void)
{
 switch (m_FileHasher->operationMode())
 {
  case CFileHasher::Computation:
  {
   QModelIndex index = ui->treeViewDirs->currentIndex();
   ui->listViewComputeSelectionSource->setRootIndex(index);
   m_DirModel->setFilter(QDir::Dirs|QDir::NoDotAndDotDot|QDir::Files);
   m_DirModel->setSorting(QDir::DirsFirst);
   m_SelectionModel->clearSelection();
   //
   m_FileHasher->clearSelection();
   ui->listWidgetComputeSelection->clear();
   for (int i = 0, n = m_FileHasher->selectedFilesCount(); i < n; i++)
   {
    ui->listWidgetComputeSelection->addItem(m_FileHasher->selectedFilePath(i));
   }
   setAccessible(ui->pushButtonClearList,(m_FileHasher->sourceFilesCount()>0));
   setAccessible(ui->pushButtonStartHashing,(m_FileHasher->sourceFilesCount()>0));
   ui->stackedWidget->setCurrentWidget(ui->pageComputeSelection);
   enable(ui->action_New); enable(ui->action_Open);
   disable(ui->action_Verify); disable(ui->action_Update);
   disable(ui->action_Preview); disable(ui->action_Save);
   disable(ui->action_About);
   ui->statusBar->showMessage(tr("Compute new hash: select files to process and set hash type."));
   break;
  }
  case CFileHasher::Verification:
  {
   ui->listWidgetSelection->clear();
   for (int i = 0, n = m_FileHasher->savedFilesCount(); i < n; i++)
   {
    QString fileName = m_FileHasher->savedFilePath(i);
    ui->listWidgetSelection->addItem(fileName);
    ui->listWidgetSelection->item(i)->setFlags(Qt::ItemIsUserCheckable|Qt::ItemIsEnabled);
    ui->listWidgetSelection->item(i)->setCheckState(Qt::Checked);
   }
   //
   changeUpdateMode(ui->comboBoxUpdateMode->currentIndex());
   ui->stackedWidget->setCurrentWidget(ui->pageVerifySelection);
   enable(ui->action_New); enable(ui->action_Open);
   disable(ui->action_Verify); disable(ui->action_Update);
   disable(ui->action_Preview); disable(ui->action_Save);
   disable(ui->action_About);
   ui->statusBar->showMessage(tr("Verify hash: select files to process and set hash type."));
   break;
  }
  case CFileHasher::Updating:
  {
   // exclude missing files
   ui->statusBar->showMessage(tr("Checking if all files are accessible..."));
   QApplication::processEvents();
   m_FileHasher->selectFromSavedFiles();
   m_FileHasher->collectMissingAndExistingFiles();
   //
   ui->textBrowserMissingFiles->clear();
   QStringList missingFiles;
   int n = m_FileHasher->missingFilesCount();
   if (n > 0)
   {
    //missingFiles << tr("Following files (%1) from listed in ChecksumFile (%2) are not found:");
    missingFiles << tr("%1 files out of %2 listed in checksum file are found and %3 files are missing:")
    .arg(m_FileHasher->savedFilesCount()-m_FileHasher->missingFilesCount())
    .arg(m_FileHasher->savedFilesCount()).arg(m_FileHasher->missingFilesCount());
    missingFiles << "";
    for (int i = 0; i < n; i++)
    {
     missingFiles << m_FileHasher->missingFilePath(i);
    }
   }
   else
   {
    missingFiles << tr("All files listed in checksum file are found, none missing.");
   }
   // bring up to ui //
   ui->textBrowserMissingFiles->setPlainText(missingFiles.join("\n"));
   ui->stackedWidget->setCurrentWidget(ui->pageUpdateOptions);
   ui->statusBar->showMessage(tr("Select update options and hash type."));
   break;
  }
 }
 //ui->pushButtonPauseHashing->setIcon(m_IconContinue);
 //ui->pushButtonPauseHashing->setText(tr("Continue"));
 //enable(ui->pushButtonPauseHashing);
}

void MainWindow::switchToNewChecksumFileScreen(void)
{
 m_FileHasher->setOperationMode(CFileHasher::Computation);
 //m_FileHasher->clearScanSelection();//fixed in selectRootDir(void)//
 m_DirModel->setFilter(QDir::Dirs|QDir::NoDotAndDotDot);
 //changeRootDir(ui->treeViewDirs->currentIndex());
 changeRootDir(m_DirModel->index(m_FileHasher->rootPath()));
 ui->stackedWidget->setCurrentWidget(ui->pageRootDir);
 disable(ui->action_New); disable(ui->action_Verify);
 disable(ui->action_Update); disable(ui->action_Preview);
 disable(ui->action_Save);
 enable(ui->action_Open); enable(ui->action_About);

 ui->statusBar->showMessage(tr("Compute hashes: select root directory to continue and click \"Select\" button."));
}

void MainWindow::openChecksumFile(void)
{
 if (QDialog::Accepted == m_OpenFileDialog->exec())
 {
  QStringList files = m_OpenFileDialog->selectedFiles();
  if (files.count() > 0)
  {
   m_ChecksumFileName = QDir::toNativeSeparators(files.at(0));
   ui->statusBar->showMessage(tr("Opening file \"%1\" ...").arg(m_ChecksumFileName));
   QApplication::processEvents();
   int filterIndex = m_OpenFileDialog->nameFilters().indexOf(m_OpenFileDialog->selectedFilter());
   if (m_FileHasher->openChecksumFile(m_ChecksumFileName,filterIndex))
   {
    ui->textEditChecksumFile->setPlainText(m_FileHasher->checksumFile().join("\n"));
    int hashType = m_FileHasher->hashAlgorithm();
    ui->comboBoxComputeHashType->setCurrentIndex(hashType);
    ui->comboBoxVerifyHashType->setCurrentIndex(hashType);
    ui->comboBoxUpdateHashType->setCurrentIndex(hashType);
    //
    // workaround: assume this mode before it is actually activated
    // to allow input file reloading when encoding changes
    m_FileHasher->setOperationMode(CFileHasher::Verification);

    ui->tabWidgetReports->setCurrentWidget(ui->tabChecksumFile);
    ui->stackedWidget->setCurrentWidget(ui->pageReports);
    ui->tabResultsBrowser->setEnabled(false);
    ui->tabFileLists->setEnabled(false);
    // disable output formatting controls
    ui->checkBoxWriteHeader->setEnabled(false);
    ui->comboBoxCommentCharacter->setEnabled(false);
    ui->comboBoxDateTimeFormat->setEnabled(false);
    ui->checkBoxWriteHashAlgorithm->setEnabled(false);
    ui->checkBoxWriteAsteriskDelimiter->setEnabled(false);
    // enable for compatibility
    ui->comboBoxHashEncoding->setEnabled(true);
    //
    disable(ui->action_Preview); disable(ui->action_About);

    enable(ui->action_New); enable(ui->action_Open);
    enable(ui->action_Verify); enable(ui->action_Update);
    enable(ui->action_Save);
    //
    ui->statusBar->showMessage(tr("Successfully opened file \"%1\"").arg(m_ChecksumFileName));
   }
   else
   {
    ui->statusBar->showMessage(tr("Could not open file \"%1\"").arg(m_ChecksumFileName));
    disable(ui->action_Verify); disable(ui->action_Update);
    disable(ui->action_Preview); disable(ui->action_Save);
    disable(ui->action_About);
    enable(ui->action_New); enable(ui->action_Open);
 }}}
}

void MainWindow::verifyFileHashes(void)
{
 m_FileHasher->setOperationMode(CFileHasher::Verification);
 //
 QFileInfo fileInfo(m_ChecksumFileName);
 //ui->treeViewDirs->setCurrentIndex(m_DirModel->index(fileInfo.absolutePath()));
 changeRootDir(m_DirModel->index(fileInfo.absolutePath()));
 //
 m_DirModel->setFilter(QDir::Dirs|QDir::NoDotAndDotDot);
 ui->stackedWidget->setCurrentWidget(ui->pageRootDir);
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_Save);
 disable(ui->action_About);
 enable(ui->action_New); enable(ui->action_Open);
 //
 ui->statusBar->showMessage(tr("Verify hashes: select root directory to continue and click \"Select\" button."));
}

void MainWindow::updateFileHashes(void)
{
 m_FileHasher->setOperationMode(CFileHasher::Updating);
 //
 QFileInfo fileInfo(m_ChecksumFileName);
 ui->treeViewDirs->setCurrentIndex(m_DirModel->index(fileInfo.absolutePath()));
 m_DirModel->setFilter(QDir::Dirs|QDir::NoDotAndDotDot);
 //
 ui->stackedWidget->setCurrentWidget(ui->pageRootDir);
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_Save);
 disable(ui->action_About);
 enable(ui->action_New); enable(ui->action_Open);
 //
 ui->statusBar->showMessage(tr("Updates hashes: select root directory to continue and click \"Select\" button."));
}

void MainWindow::refreshChecksumFile(void)
{
 m_FileHasher->doWriteHeader() = ui->checkBoxWriteHeader->isChecked();
 m_FileHasher->doWriteHashAlgorithm() = ui->checkBoxWriteHashAlgorithm->isChecked();
 ui->checkBoxWriteAsteriskDelimiter->setEnabled(!ui->checkBoxWriteHashAlgorithm->isChecked());
 m_FileHasher->doWriteAsteriskDelimiter() = ui->checkBoxWriteAsteriskDelimiter->isChecked();
 m_FileHasher->generateChecksumFile();
 // bring up to ui //
 ui->textEditChecksumFile->clear();
 ui->textEditChecksumFile->setPlainText(m_FileHasher->checksumFile().join("\n"));
}

void MainWindow::refreshChecksumFile1(int index)
{
 /* Do not use 'index' parameter! This slot is just a substitute signal reciever
    for actually required function 'void MainWindow::refreshChecksumFile(void)' */
 CByteArrayCodec::Encoding encoding = CByteArrayCodec::Base16low;
 switch (ui->comboBoxHashEncoding->currentIndex())
 {
  default:
  case 0: { encoding = CByteArrayCodec::Base16; break; }
  case 1: { encoding = CByteArrayCodec::Base16low; break; }
  case 2: { encoding = CByteArrayCodec::Base32; break; }
  case 3: { encoding = CByteArrayCodec::Base32hex; break; }
  case 4: { encoding = CByteArrayCodec::Base64; break; }
  case 5: { encoding = CByteArrayCodec::Base64url; break; }
 }
 m_FileHasher->setHashEncoding(encoding);
 //
 switch (m_FileHasher->operationMode())
 {
  case CFileHasher::Computation:
  case CFileHasher::Updating:
  {
   m_FileHasher->commentCharacter() = ui->comboBoxCommentCharacter->currentText()[0];
   m_FileHasher->dateTimeFormat() = ui->comboBoxDateTimeFormat->currentText();
   refreshChecksumFile();
   break;
  }
  case CFileHasher::Verification:
  {
   m_FileHasher->reopenChecksumFile();
   break;
  }
 }
}

void MainWindow::previewChecksumFile(void)
{
 refreshChecksumFile1(0);
 // bring up to ui //
 ui->stackedWidget->setCurrentWidget(ui->pageReports);
 ui->statusBar->showMessage(tr("Click \"Save\" button to write checksums to a file or click \"New\" or \"Open\" button to start over."));
 //
 disable(ui->action_Verify); disable(ui->action_Update);
 disable(ui->action_Preview); disable(ui->action_About);

 enable(ui->action_New); enable(ui->action_Open); enable(ui->action_Save);
}

void MainWindow::saveChecksumFile(void)
{
 if (ui->tabWidgetReports->currentWidget() == ui->tabResultsBrowser)
 {
  QString fileName = QFileDialog::getSaveFileName(this,tr("Save HTML report"),
   "",tr("HTML files (*.html);;All files (*)"));
  if (!fileName.isEmpty())
  {
   m_FileHasher->saveHtmlReport(fileName);
  }
  return;
 }
 if (ui->tabWidgetReports->currentWidget() == ui->tabFileLists)
 {
  QString fileName = QFileDialog::getSaveFileName(this,tr("Save list of files"),
   "",tr("Text files (*.txt *.lst);;All files (*)"));
  if (!fileName.isEmpty())
  {
   QWidget *currentWidget = ui->tabWidgetFileLists->currentWidget();
   if (currentWidget == ui->tabAllFiles)
    m_FileHasher->saveFileList(fileName,m_FileHasher->listAllFiles());
   if (currentWidget == ui->tabGoodFiles)
    m_FileHasher->saveFileList(fileName,m_FileHasher->listGoodFiles());
   if (currentWidget == ui->tabBrokenFiles)
    m_FileHasher->saveFileList(fileName,m_FileHasher->listBrokenFiles());
   if (currentWidget == ui->tabHashMismatch)
    m_FileHasher->saveFileList(fileName,m_FileHasher->listHashMismatchedFiles());
   if (currentWidget == ui->tabAccessFailure)
    m_FileHasher->saveFileList(fileName,m_FileHasher->listAccessFailedFiles());
  }
  return;
 }
 //
 QString ext = CCryptographicHash::name(m_FileHasher->hashAlgorithm()).toLower();
 m_SaveFileDialog->setDirectory(m_FileHasher->rootPath());
 m_SaveFileDialog->selectNameFilter(
  m_SaveFileDialog->nameFilters().at(m_FileHasher->hashAlgorithm()));
 {
  QString fileName = "checksum."+ext;
  int n = m_FileHasher->targetFilesCount();
  if (n > 1)
  {
   fileName = m_FileHasher->rootPath();
   if (fileName.endsWith(QDir::separator())) fileName = fileName.left(fileName.size()-1);
   QFileInfo fileInfo(fileName);
   fileName = fileInfo.fileName();
   fileName.append(".").append(ext);
  }
  else
  {
   fileName = m_FileHasher->sourceFileName(0)+"."+ext;
  }
  m_SaveFileDialog->selectFile(fileName);
 }
 if (QDialog::Accepted == m_SaveFileDialog->exec())
 {
  QStringList files = m_SaveFileDialog->selectedFiles();
  if (files.count() > 0)
  {
   QString fileName = files.at(0);
   if (!fileName.endsWith("."+ext,Qt::CaseInsensitive))
   {
    fileName.append(".").append(ext);
   }
   m_FileHasher->saveChecksumFile(fileName);
 }}
}

void MainWindow::selectAllFiles(void)
{
 ui->listViewComputeSelectionSource->selectAll();
}

void MainWindow::showScanSelection(void)
{
 ui->listWidgetComputeSelection->clear();
 for (int i = 0, n = m_FileHasher->selectedFilesCount(); i < n; i++)
 {
  QString item = m_FileHasher->selectedFilePath(i);
  ui->listWidgetComputeSelection->addItem(item);
 }
}

void MainWindow::selectFilesToScan(const bool recursively)
{
 QModelIndexList selection = m_SelectionModel->selectedIndexes();
 for (int i = 0, n = selection.count(); i < n; i++)
 {
  QModelIndex index = selection.at(i);
  if (m_DirModel->isDir(index))
  {
   if (m_DirModel->hasChildren(index))
   {
    m_FileHasher->selectDirectory(m_DirModel->filePath(index),recursively);
  }}
  else
  {
   m_FileHasher->selectFile(m_DirModel->filePath(index));
  }
 }
 m_FileHasher->removeDuplicatesFromSelection();
 showScanSelection();
 bool filesSelected = (m_FileHasher->selectedFilesCount()>0);
 setAccessible(ui->pushButtonClearList,filesSelected);
 setAccessible(ui->pushButtonStartHashing,filesSelected);
}

void MainWindow::addFile(const QModelIndex& index)
{
 m_SelectionModel->select(index,QItemSelectionModel::Select);
 selectFilesToScan(true);
}

void MainWindow::addFiles(void)
{
 selectFilesToScan(false);
}

void MainWindow::addRecursively(void)
{
 selectFilesToScan(true);
}

void MainWindow::removeFile(QListWidgetItem * item)
{
 int index = ui->listWidgetComputeSelection->row(item);
 m_FileHasher->deselectFile(index);
 //ui->listWidgetComputeSelection->removeItemWidget(item);
 ui->listWidgetComputeSelection->takeItem(index);
 delete item;
 bool filesSelected = (m_FileHasher->selectedFilesCount()>0);
 setAccessible(ui->pushButtonClearList,filesSelected);
 setAccessible(ui->pushButtonStartHashing,filesSelected);
}

void MainWindow::clearList(void)
{
 m_FileHasher->clearSelection();
 ui->listWidgetComputeSelection->clear();
 bool filesSelected = (m_FileHasher->selectedFilesCount()>0);
 setAccessible(ui->pushButtonClearList,filesSelected);
 setAccessible(ui->pushButtonStartHashing,filesSelected);
}

void MainWindow::verifyItem(QListWidgetItem* item)
{
 int count = 0;
 for (int i = 0, n = ui->listWidgetSelection->count(); i < n; i++)
 {
  if (Qt::Checked == ui->listWidgetSelection->item(i)->checkState()) count++;
 }
 setAccessible(ui->pushButtonStartVerification,(count > 0));
}

void MainWindow::verifyAll(void)
{
 const int count = ui->listWidgetSelection->count();
 for (int i = 0; i < count; i++)
 {
  ui->listWidgetSelection->item(i)->setCheckState(Qt::Checked);
 }
 setAccessible(ui->pushButtonStartVerification,(count > 0));
}

void MainWindow::verifyNone(void)
{
 for (int i = 0, n = ui->listWidgetSelection->count(); i < n; i++)
 {
  ui->listWidgetSelection->item(i)->setCheckState(Qt::Unchecked);
 }
 disable(ui->pushButtonStartVerification);
}

void MainWindow::changeUpdateMode(const int index)
{
 QString hint;
 switch (index)
 {
  case 0: { hint = tr("Brief mode: recalculate hashes for same files."); break; }
  case 1: { hint = tr("Deep mode: search for new files in same directories."); break; }
  case 2: { hint = tr("delta-Deep mode: search for new files in same directories, update only new files."); break; }
  case 3: { hint = tr("Complete mode: search for new files recursively, update all files."); break; }
  case 4: { hint = tr("delta-Complete mode: search for new files recursively, update only new files."); break; }
  //case 5: { hint = tr(""); break; }
 }
 ui->labelUpdateModeHint->setText(hint);
}

void MainWindow::showCounters(void)
{
 ui->labelUnchecked->setText(tr("Unchecked (%1)").arg(m_FileHasher->uncheckedFileCount()));
 ui->labelProcessing->setText(tr("Processing (%1)").arg(m_FileHasher->processingFileCount()));
 ui->labelGood->setText(tr("Good (%1)").arg(m_FileHasher->goodFileCount()));
 ui->labelError->setText(tr("Error (%1)").arg(m_FileHasher->brokenFileCount()));
}

void MainWindow::clearReport(void)
{
 ui->textBrowserResults->clear();
}

void MainWindow::showReport(void)
{
 ui->textBrowserResults->setHtml(m_FileHasher->generateHtmlReport());
}

void MainWindow::clearFileLists(void)
{
 ui->listWidgetAllFiles->clear();
 ui->listWidgetGoodFiles->clear();
 ui->listWidgetBrokenFiles->clear();
 ui->listWidgetHashMismatchedFiles->clear();
 ui->listWidgetAccessFailedFiles->clear();
}

void MainWindow::showFileLists(void)
{
 clearFileLists();
 ui->listWidgetAllFiles->addItems(m_FileHasher->listAllFiles());
 ui->listWidgetGoodFiles->addItems(m_FileHasher->listGoodFiles());
 ui->listWidgetBrokenFiles->addItems(m_FileHasher->listBrokenFiles());
 ui->listWidgetHashMismatchedFiles->addItems(m_FileHasher->listHashMismatchedFiles());
 ui->listWidgetAccessFailedFiles->addItems(m_FileHasher->listAccessFailedFiles());
}

void MainWindow::startHashing(void)
{
 if (m_FileHasher->operationMode() == CFileHasher::Updating)
 {
  int updateMode = ui->comboBoxUpdateMode->currentIndex();
  m_FileHasher->doUpdateRootDirectory() = ui->checkBoxUpdateRootDir->isChecked();
  switch (updateMode)
  {
   default:
   case 0: { m_FileHasher->setUpdateMode(CFileHasher::Brief); break; }
   case 1: { m_FileHasher->setUpdateMode(CFileHasher::Deep); break; }
   case 2: { m_FileHasher->setUpdateMode(CFileHasher::DeltaDeep); break; }
   case 3: { m_FileHasher->setUpdateMode(CFileHasher::Complete); break; }
   case 4: { m_FileHasher->setUpdateMode(CFileHasher::DeltaComplete); break; }
  }
 }
 //
 switch (m_FileHasher->operationMode())
 {
  case CFileHasher::Computation:
  case CFileHasher::Updating:
  {
   m_FileHasher->beforeHashing();
   if (m_FileHasher->sourceFilesCount() < 1)
   {
    ui->statusBar->showMessage(tr("No files for processing."));
    return;
   }
   //
   int hashType = ui->comboBoxComputeHashType->currentIndex();
   m_FileHasher->setHashAlgorithm((CCryptographicHash::Algorithm)hashType);
   QString hashName = CCryptographicHash::name(m_FileHasher->hashAlgorithm());
   ui->tableWidget->clear();
   ui->tableWidget->setRowCount(0);
   ui->tableWidget->setColumnCount(3);
   ui->tableWidget->setRowCount(m_FileHasher->sourceFilesCount());
   ui->tableWidget->horizontalHeader()->setResizeMode(0,QHeaderView::ResizeToContents);
   ui->tableWidget->horizontalHeader()->setResizeMode(1,QHeaderView::ResizeToContents);
   ui->tableWidget->horizontalHeader()->setResizeMode(2,QHeaderView::Stretch);
   ui->tableWidget->setHorizontalHeaderItem
    (0,new QTableWidgetItem(tr("Status")));
   ui->tableWidget->setHorizontalHeaderItem
    (1,new QTableWidgetItem(tr("%1 Hash (%2)")
     .arg(CCryptographicHash::name(m_FileHasher->hashAlgorithm()))
     .arg(CByteArrayCodec::name(m_FileHasher->hashEncoding()))));
   ui->tableWidget->setHorizontalHeaderItem
    (2,new QTableWidgetItem(tr("File")));
   for (int i = 0, n = m_FileHasher->sourceFilesCount(); i < n; i++)
   {
    ui->tableWidget->setItem(i,0,new QTableWidgetItem(tr("Unchecked")));
    ui->tableWidget->item(i,0)->setIcon(*m_IconUnchecked);
    ui->tableWidget->setItem(i,1,new QTableWidgetItem(""));
    ui->tableWidget->setItem(i,2,new QTableWidgetItem(m_FileHasher->sourceFilePath(i)));
   }
   //
   ui->stackedWidget->setCurrentWidget(ui->pageHashing);
   disable(ui->action_New); disable(ui->action_Open);
   enable(ui->pushButtonPauseHashing); enable(ui->pushButtonStopHashing);
   //
   m_FileHasher->resetCounters();
   showCounters();
   m_FileHasher->startHashing();
   break;
  }
  case CFileHasher::Verification:
  {
   int hashType = ui->comboBoxVerifyHashType->currentIndex();
   m_FileHasher->setHashAlgorithm((CCryptographicHash::Algorithm)hashType);
   QList<bool> selection;
   for (int i = 0, n = ui->listWidgetSelection->count(); i < n; i++)
   {
    Qt::CheckState fileCheckState = ui->listWidgetSelection->item(i)->checkState();
    bool fileSelected = (fileCheckState == Qt::Checked);
    selection.append(fileSelected);
   }
   m_FileHasher->selectFromSavedFiles(selection);
   m_FileHasher->beforeHashing();
   //
   QString hashName = CCryptographicHash::name(m_FileHasher->hashAlgorithm());
   QString hashEnc = CByteArrayCodec::name(m_FileHasher->hashEncoding());
   ui->tableWidget->clear();
   ui->tableWidget->setRowCount(0);
   ui->tableWidget->setColumnCount(4);
   ui->tableWidget->setRowCount(m_FileHasher->sourceFilesCount());
   ui->tableWidget->horizontalHeader()->setResizeMode(0,QHeaderView::ResizeToContents);
   ui->tableWidget->horizontalHeader()->setResizeMode(1,QHeaderView::ResizeToContents);
   ui->tableWidget->horizontalHeader()->setResizeMode(2,QHeaderView::ResizeToContents);
   ui->tableWidget->horizontalHeader()->setResizeMode(3,QHeaderView::Stretch);
   ui->tableWidget->setHorizontalHeaderItem
    (0,new QTableWidgetItem(tr("Status")));
   ui->tableWidget->setHorizontalHeaderItem
    (1,new QTableWidgetItem(tr("%1 Hash (%2)").arg(hashName).arg(hashEnc)));
   ui->tableWidget->setHorizontalHeaderItem
    (2,new QTableWidgetItem(tr("Saved %1 hash (%2)").arg(hashName).arg(hashEnc)));
   ui->tableWidget->setHorizontalHeaderItem
    (3,new QTableWidgetItem(tr("File")));
   for (int i = 0, n = m_FileHasher->sourceFilesCount(); i < n; i++)
   {
    ui->tableWidget->setItem(i,0,new QTableWidgetItem(tr("Unchecked")));
    ui->tableWidget->item(i,0)->setIcon(*m_IconUnchecked);
    ui->tableWidget->setItem(i,1,new QTableWidgetItem(""));
    ui->tableWidget->setItem(i,2,new QTableWidgetItem(m_FileHasher->sourceFileHash(i)));
    ui->tableWidget->setItem(i,3,new QTableWidgetItem(m_FileHasher->sourceFilePath(i)));
   }
   //
   ui->stackedWidget->setCurrentWidget(ui->pageHashing);
   disable(ui->action_New); disable(ui->action_Open);
   enable(ui->pushButtonPauseHashing); enable(ui->pushButtonStopHashing);
   ui->tableWidget->resizeColumnsToContents();
   //
   m_FileHasher->resetCounters();
   showCounters();
   m_FileHasher->startHashing();
   break;
  }
 }
 //
 ui->progressBarFile->setValue(0);
 ui->progressBarTotal->setValue(0);
 //
 ui->listWidgetAllFiles->clear();
 ui->listWidgetGoodFiles->clear();
 ui->listWidgetBrokenFiles->clear();
 ui->listWidgetHashMismatchedFiles->clear();
 ui->listWidgetAccessFailedFiles->clear();
 //
 ui->pushButtonPauseHashing->setIcon(*m_IconPause);
 ui->pushButtonPauseHashing->setText(tr("Pause"));
}

void MainWindow::pauseHashing(void)
{
 if (m_FileHasher->hashingStopped())
 {
  startHashing();
  return;
 }
 //
 m_FileHasher->pauseHashing();
 //
 if (m_FileHasher->hashingPaused())
 {
  ui->pushButtonPauseHashing->setIcon(*m_IconContinue);
  ui->pushButtonPauseHashing->setText(tr("Continue"));
 }
 else
 {
  ui->pushButtonPauseHashing->setIcon(*m_IconPause);
  ui->pushButtonPauseHashing->setText(tr("Pause"));
 }
}

void MainWindow::stopHashing(void)
{
 if (m_FileHasher->hashingPaused()) pauseHashing();
 m_FileHasher->stopHashing();
 ui->pushButtonPauseHashing->setIcon(*m_IconRestart);
 ui->pushButtonPauseHashing->setText(tr("Restart"));
 enable(ui->pushButtonPauseHashing);
 disable(ui->pushButtonStopHashing);
 ui->statusBar->showMessage("");
}

void MainWindow::beginFileProcessing(void)
{
 int fileIndex = m_FileHasher->currentFileIndex();
 ui->tableWidget->item(fileIndex,0)->setIcon(*m_IconProcessing);
 ui->tableWidget->item(fileIndex,0)->setText(tr("Processing"));
 QFileInfo fileInfo(m_FileHasher->currentFilePath());
 QFontMetrics fontMetrics(ui->labelFileSize->font());
 QString rawText(fileInfo.fileName());
 if (fontMetrics.width(rawText) > ui->labelFileName->width())
 {
  ui->labelFileName->setText(DecorateFileName(rawText,fontMetrics,
                             ui->labelFileName->width()));
 }
 else
 {
  ui->labelFileName->setText(rawText);
 }
 qint64 fileSize = m_FileHasher->currentFileSize();
 ui->labelFileSize->setText(FileSizeToString(fileSize));
 ui->statusBar->showMessage(tr("Processing file %1 of %2 ...")
  .arg(fileIndex+1).arg(m_FileHasher->sourceFilesCount()));
 showCounters();
}

void MainWindow::updateFileProgress(void)
{
 ui->progressBarFile->setValue(m_FileHasher->currentFileProgress());
}

void MainWindow::doneFileProcessing(void)
{
 int fileIndex = m_FileHasher->currentFileIndex();
 ui->progressBarTotal->setValue(m_FileHasher->totalFileProgress());
#ifdef FEATURE_AUTOSCROLL
 {
  QScrollBar *sb = ui->tableWidget->verticalScrollBar();
  sb->setValue(sb->value()+sb->singleStep());
 }
#endif
 QString fileName = m_FileHasher->sourceFilePath(fileIndex);
 QString fileHash = m_FileHasher->calculatedFileHash(fileIndex);
 QString statusText;
 ui->listWidgetAllFiles->addItem(fileName);
 switch (m_FileHasher->currentFileStatus())
 {
  case CFileHasher::Good:
  {
   ui->tableWidget->item(fileIndex,1)->setText(fileHash);
   ui->tableWidget->item(fileIndex,0)->setIcon(*m_IconGood);
   statusText = m_FileHasher->statusName(m_FileHasher->currentFileStatus());//tr("Good");
   break;
  }
  case CFileHasher::NoAccess:
  {
   ui->listWidgetAccessFailedFiles->addItem(fileName);
   ui->tableWidget->item(fileIndex,0)->setIcon(*m_IconError);
   statusText = m_FileHasher->statusName(m_FileHasher->currentFileStatus());//tr("Inaccessible");
   break;
  }
  case CFileHasher::HashMatch:
  {
   ui->tableWidget->item(fileIndex,1)->setText(fileHash);
   ui->tableWidget->item(fileIndex,0)->setIcon(*m_IconGood);
   statusText = m_FileHasher->statusName(m_FileHasher->currentFileStatus());//tr("Match");
   break;
  }
  case CFileHasher::HashMismatch:
  {
   ui->tableWidget->item(fileIndex,1)->setText(fileHash);
   ui->tableWidget->item(fileIndex,0)->setIcon(*m_IconError);
   statusText = m_FileHasher->statusName(m_FileHasher->currentFileStatus());//tr("Mismatch");
   break;
  }
 }
 ui->tableWidget->item(fileIndex,0)->setText(statusText);
 ui->tableWidget->resizeColumnsToContents();
 showCounters();
 QApplication::processEvents();
 //
 if (m_FileHasher->hashingStopped())
 {
  ui->statusBar->showMessage(tr("Creating report ..."));
  //
  m_FileHasher->doKeepMissingFiles() = !ui->checkBoxRemoveMissingFiles->isChecked();
  m_FileHasher->afterHashing();  
  QApplication::processEvents();
  showReport();
  showFileLists();
  ui->statusBar->showMessage("");
  //
  switch (m_FileHasher->operationMode())
  {
   case CFileHasher::Computation:
   case CFileHasher::Updating:
   {
    setAccessible(ui->action_Preview,m_FileHasher->hashingStopped());
    disable(ui->action_Save);
    disable(ui->pushButtonPauseHashing);
    disable(ui->pushButtonStopHashing);
    ui->statusBar->showMessage(tr("File processing is finished. Click \"Report\" button to see results."));
    break;
   }
   case CFileHasher::Verification:
   {
    enable(ui->action_Preview);
    //disable(ui->action_Preview);
    disable(ui->action_Save);
    enable(ui->action_About);
    disable(ui->pushButtonPauseHashing);
    disable(ui->pushButtonStopHashing);
    ui->statusBar->showMessage(tr("File processing is finished."));
    break;
   }
  }
  enable(ui->action_New);
  enable(ui->action_Open);
  ui->pushButtonPauseHashing->setIcon(*m_IconRestart);
  ui->pushButtonPauseHashing->setText(tr("Restart"));
  enable(ui->pushButtonPauseHashing);
  showCounters();
  ui->tabWidgetReports->setCurrentWidget(ui->tabResultsBrowser);
  ui->tabResultsBrowser->setEnabled(true);
  ui->tabFileLists->setEnabled(true);
  // enable output formatting controls
  ui->checkBoxWriteHeader->setEnabled(true);
  ui->comboBoxCommentCharacter->setEnabled(true);
  ui->comboBoxDateTimeFormat->setEnabled(true);
  ui->checkBoxWriteHashAlgorithm->setEnabled(true);
  ui->checkBoxWriteAsteriskDelimiter->setEnabled(true);
  ui->comboBoxHashEncoding->setEnabled(true);
 }
}

