/*
    This file is part of JasonQt

    Copyright: Jason

    Contact email: 188080501@qq.com

    GNU Lesser General Public License Usage
    Alternatively, this file may be used under the terms of the GNU Lesser
    General Public License version 2.1 or version 3 as published by the Free
    Software Foundation and appearing in the file LICENSE.LGPLv21 and
    LICENSE.LGPLv3 included in the packaging of this file. Please review the
    following information to ensure the GNU Lesser General Public License
    requirements will be met: https://www.gnu.org/licenses/lgpl.html and
    http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
*/

#include "JasonQt_WinPcap.h"

using namespace JasonQt_WinPcap;

#include "pcap.h"

void UdpServer::setOnReceivedCallback(const std::function<void (const char *, const int &, const UdpHeader *, const IpHeader *)> &callback)
{
    m_onReceivedCallback = callback;
}

void UdpServer::setOnReceivedCallback(const std::function<void (const char *, const int &)> &callback)
{
    m_onReceivedCallback = [=](const char *data, const int &size, const UdpHeader *, const IpHeader *)
    {
        callback(data, size);
    };
}

QStringList UdpServer::availableDevices()
{
    QStringList buf;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        return QStringList();
    }

    for(d = alldevs; d; d=d->next)
    {
        buf.push_back((d->description) ? (d->description) : (""));
    }

    return buf;
}

void UdpServer::setCurrentDevice(const int &index)
{
    m_currentDevice = index + 1;
}

bool UdpServer::listen(const int &port)
{
    if(this->isRunning())
    {
        qDebug("UdpServer::listen: error1");
        return false;
    }

    if((port <= 0) && (port > 65536))
    {
        qDebug("UdpServer::listen: error2");
        return false;
    }

    QEventLoop eventLoop;

    m_port = port;
    m_eventLoop = &eventLoop;

    this->start();

    return eventLoop.exec(QEventLoop::ExcludeUserInputEvents);
}

void UdpServer::run()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t netmask;
    char packet_filter[] = "ip and udp";
    struct bpf_program fcode;

    // Retrieve the device list
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print the list
    for(d = alldevs; d; d=d->next)
    {
        ++i;
//        qDebug("%d. %s", i, d->name);
//        if (d->description)
//            qDebug(" (%s)\n", d->description);
//        else
//            qDebug(" (No description available)");
    }

    if(i==0)
    {
        qDebug("No interfaces found! Make sure WinPcap is installed.");
        return m_eventLoop->exit(false);
    }

//    qDebug("Enter the interface number (1-%d):",i);
//    scanf("%d", &inum);
    inum = m_currentDevice;

    // Check if the user specified a valid adapter
    if(inum < 1 || inum > i)
    {
        qDebug("Adapter number out of range.");

        // Free the device list
        pcap_freealldevs(alldevs);
        return m_eventLoop->exit(false);
    }

    // Jump to the selected adapter
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    // Open the adapter
    if ((adhandle= pcap_open_live(d->name,  // name of the device
                                  65535,    // portion of the packet to capture.
                                  // 65536 grants that the whole packet will be captured on all the MACs.
                                  1,        // promiscuous mode (nonzero means promiscuous)
                                  1000,     // read timeout
                                  errbuf    // error buffer
                                  )) == NULL)
    {
        qDebug("Unable to open the adapter. Is not supported by WinPcap");

        // Free the device list
        pcap_freealldevs(alldevs);
        return m_eventLoop->exit(false);
    }

    // Check the link layer. We support only Ethernet for simplicity.
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        qDebug("This program works only on Ethernet networks.");

        // Free the device list
        pcap_freealldevs(alldevs);
        return m_eventLoop->exit(false);
    }

    if(d->addresses != NULL)
    {
        // Retrieve the mask of the first address of the interface
        netmask=((SockAddr *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        // If the interface is without addresses we suppose to be in a C class network
        netmask=0xffffff;
    }

    // compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        qDebug("Unable to compile the packet filter. Check the syntax.");

        // Free the device list
        pcap_freealldevs(alldevs);
        return m_eventLoop->exit(false);
    }

    // set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        qDebug("Error setting the filter.");

        // Free the device list
        pcap_freealldevs(alldevs);
        return m_eventLoop->exit(false);
    }

//    qDebug("listening on %s...\n", d->description);

    // At this point, we don't need any more the device list. Free it
    pcap_freealldevs(alldevs);

    m_eventLoop->exit(true);

    // start the capture
    pcap_loop(adhandle, 0, UdpServer::onReceived, (uint8_t *)this);
}

void UdpServer::onReceived(uint8_t *param, const pcap_pkthdr *, const uint8_t *rawData)
{
    auto server = (UdpServer *)param;

    // retireve the position of the ip header
    IpHeader const *ipHeader = (IpHeader *)(rawData + 14);

    // retireve the position of the udp header
    uint32_t ipHeaderLen = (ipHeader->ver_ihl & 0xf) * 4;
    UdpHeader const *udpHeader = (UdpHeader *)((uint8_t*)ipHeader + ipHeaderLen);

    if(ntohs(udpHeader->destinationPort) != server->m_port) { return; }

    int dataSize = ntohs(udpHeader->datagramLength) - 8;

    if(server->m_onReceivedCallback == NULL)
    {
        qDebug("UdpServer::onReceived: Callback is NULL");
        return;
    }

    server->m_onReceivedCallback(((const char *)rawData) + 42, dataSize, udpHeader, ipHeader);
}
