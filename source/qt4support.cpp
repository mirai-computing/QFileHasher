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

/*
    Following piece of code to support earler versions of Qt toolkit
    is based on Qt 4.5 implementation and tested at least against Qt 4.4.
    It is not guaranteed this will be enough for Qt 4.3 or earlier version.
*/

#include <QtCore/QSet>
#include "qt4support.h"

#if QT_VERSION < 0x040500
#ifdef Q_OS_UNIX
#include <sched.h>
#endif
#ifdef Q_OS_WINDOWS
#include <windows.h>
#endif

void yieldCurrentThread(void)
{
#ifdef Q_OS_UNIX
 sched_yield();
#endif
#ifdef Q_OS_WINDOWS
 SwitchToThread();
#endif
}

int qt45_removeDuplicates(QStringList& list)
{
 int n = list.size(), j = 0;
 QSet<QString> seen;
 seen.reserve(n);
 for (int i = 0; i < n; i++)
 {
  const QString &s = list.at(i);
  if (seen.contains(s)) continue;
  seen.insert(s);
  if (j!=i) list[j] = s;
  j++;
 }
 if (n!=j) list.erase(list.begin()+j,list.end());
 return n - j;
}
#endif

int removeDuplicates(QStringList& list)
{
#if QT_VERSION < 0x040500
 return qt45_removeDuplicates(list);
#else
 return list.removeDuplicates();
#endif
}

