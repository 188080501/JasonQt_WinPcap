QT += core
QT -= gui

include(./JasonQt/JasonQt.pri)

TARGET = JasonQt_WinPcap
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp
