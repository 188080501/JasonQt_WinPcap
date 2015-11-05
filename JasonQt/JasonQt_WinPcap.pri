#
#   This file is part of JasonQt
#
#   Copyright: Jason
#
#   Contact email: 188080501@qq.com
#
#   GNU Lesser General Public License Usage
#   Alternatively, this file may be used under the terms of the GNU Lesser
#   General Public License version 2.1 or version 3 as published by the Free
#   Software Foundation and appearing in the file LICENSE.LGPLv21 and
#   LICENSE.LGPLv3 included in the packaging of this file. Please review the
#   following information to ensure the GNU Lesser General Public License
#   requirements will be met: https://www.gnu.org/licenses/lgpl.html and
#   http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
#

SOURCES += $$PWD/JasonQt_WinPcap/JasonQt_WinPcap.cpp

HEADERS += $$PWD/JasonQt_WinPcap/JasonQt_WinPcap.h

INCLUDEPATH += $$PWD/JasonQt_WinPcap/ \
    $$PWD/JasonQt_WinPcap/WinPcap/Include

LIBS += $$PWD/JasonQt_WinPcap/WinPcap/IPHlpApi.lib
LIBS += $$PWD/JasonQt_WinPcap/WinPcap/odbc32.lib
LIBS += $$PWD/JasonQt_WinPcap/WinPcap/odbccp32.lib
LIBS += $$PWD/JasonQt_WinPcap/WinPcap/Packet.lib
LIBS += $$PWD/JasonQt_WinPcap/WinPcap/wpcap.lib
LIBS += $$PWD/JasonQt_WinPcap/WinPcap/WS2_32.lib
LIBS += $$PWD/JasonQt_WinPcap/WinPcap/WSock32.lib
