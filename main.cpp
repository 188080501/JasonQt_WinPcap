// Qt lib import
#include <QCoreApplication>

// JasonQt lib import
#include "JasonQt_WinPcap.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    JasonQt_WinPcap::UdpServer udpServer;

    // Get available devices
    qDebug() << udpServer.availableDevices();

    // Set device index (Default: 0)
//    udpServer.setCurrentDevice(1);

    // Set on received callback
    udpServer.setOnReceivedCallback([](const char *data, const int &size)
    {
        qDebug() << QByteArray(data, size);
    });

    // Listen
    qDebug() << "Listen:" << udpServer.listen(37300);

    return a.exec();
}
