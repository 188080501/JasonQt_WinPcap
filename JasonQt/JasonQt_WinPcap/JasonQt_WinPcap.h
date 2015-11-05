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

#ifndef __JasonQt_WinPcap_h__
#define __JasonQt_WinPcap_h__

// C lib import
#include <stdint.h>

// C++ lib import
#include <functional>

// Qt lib import
#include <QThread>
#include <QEventLoop>
#include <QDebug>

struct pcap_pkthdr;

namespace JasonQt_WinPcap
{

class UdpServer: public QThread
{
public:

#pragma pack(push)
#pragma pack(1)

    struct IpAddress
    {
        uint8_t byte1;
        uint8_t byte2;
        uint8_t byte3;
        uint8_t byte4;
    };

    struct IpHeader
    {
        uint8_t	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
        uint8_t	tos;			// Type of service
        uint16_t tlen;			// Total length
        uint16_t identification;    // Identification
        uint16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
        uint8_t	ttl;			// Time to live
        uint8_t	proto;			// Protocol
        uint16_t crc;			// Header checksum
        IpAddress saddr;		// Source address
        IpAddress daddr;		// Destination address
        uint32_t op_pad;		// Option + Padding
    };

    struct UdpHeader
    {
        uint16_t sourcePort;
        uint16_t destinationPort;
        uint16_t datagramLength;
        uint16_t crc;
    };

    struct InAddr {
        union {
            struct { uint8_t  s_b1, s_b2, s_b3, s_b4; } S_un_b;
            struct { uint16_t s_w1, s_w2; } S_un_w;
            uint32_t S_addr;
        } S_un;
    };

    struct SockAddr {
        short	sin_family;
        uint16_t sin_port;
        InAddr	sin_addr;
        char	sin_zero[8];
    };

#pragma pack(pop)

private:
    std::function< void(const char *data, const int &size, const UdpHeader *udpHeader, const IpHeader *ipHeader) > m_onReceivedCallback = NULL;
    int m_currentDevice = 1;
    int m_port = 65536;
    QEventLoop *m_eventLoop = NULL;

public:
    static inline uint16_t ntohs(uint16_t netshort) { return ((netshort & 0xff00) >> 8) | ((netshort & 0xff) << 8); }

    void setOnReceivedCallback(const std::function< void(const char *data, const int &size, const UdpHeader *udpHeader, const IpHeader *ipHeader) > &callback);

    void setOnReceivedCallback(const std::function< void(const char *data, const int &size) > &callback);

    QStringList availableDevices();

    void setCurrentDevice(const int &index);

    bool listen(const int &port);

private:
    void run();

    static void onReceived(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
};

}

#endif//__JasonQt_WinPcap_h__
