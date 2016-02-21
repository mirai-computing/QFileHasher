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

#include <QtCore/QLibraryInfo>
#include <QtCore/QTranslator>
#include <QtGui/QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
 QApplication a(argc, argv);
 //
 QTranslator qtTranslator;
 QString qtTranslationName = "qt_" + QLocale::system().name();
  if (!qtTranslator.load(qtTranslationName,QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
  if (!qtTranslator.load(a.applicationDirPath()+"/"+qtTranslationName))
  qtTranslator.load(":/resources/translations/"+qtTranslationName);
 a.installTranslator(&qtTranslator);
 QTranslator appTranslator;
 QString appTranslationName = "qfilehasher_"+QLocale::system().name();
  if (!appTranslator.load(appTranslationName))
  if (!appTranslator.load(a.applicationDirPath()+"/"+appTranslationName))
  appTranslator.load(":/resources/translations/"+appTranslationName);
 a.installTranslator(&appTranslator);
 //
 MainWindow w;
 w.show();
 return a.exec();
}
