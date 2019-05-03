#pragma once

#include "ArchNetworkBSD.h"
#include "net/NetworkAddress.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "core/KeyMap.h"
#include <unistd.h>
#if HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#endif

#define ARCH_NETWORK ArchNetworkBluetooth

#define BLUE_SYNERGY_UUID	0x891e7352df8248b5ba6cc1752b6ac42e
#define BLUE_SYNERGY_CLASS_UUID 0x00003333

//! UNIX Bluetooth sockets implementation of IArchNetwork
class ArchNetworkBluetooth : public ArchNetworkBSD {

public:
        ArchNetworkBluetooth();
        virtual ~ArchNetworkBluetooth();
        virtual void init();

        // CArchNetworkBSD Overrides
        virtual ArchSocket	newSocket(EAddressFamily, ESocketType);
        virtual void		bindSocket(ArchSocket s, ArchNetAddress addr);
        virtual ArchNetAddress	newAnyAddr(EAddressFamily);
        virtual ArchNetAddress	nameToAddr(const std::string&);
        virtual std::string	addrToName(ArchNetAddress);
        virtual std::string	addrToString(ArchNetAddress);
        virtual EAddressFamily	getAddrFamily(ArchNetAddress);
        virtual void		setAddrPort(ArchNetAddress, int port);
        virtual int		getAddrPort(ArchNetAddress);
        virtual bool		isAnyAddr(ArchNetAddress);
        virtual void		listenOnSocket(ArchSocket);
        virtual bool            setNoDelayOnSocket(ArchSocket, bool);
        virtual bool		connectSocket(ArchSocket, ArchNetAddress);
        virtual ArchSocket	acceptSocket(ArchSocket s, ArchNetAddress* addr);
        virtual std::string     findDevice(const std::string& serverName);
        virtual int		findServicePort(std::string addr);
        virtual void            registerBluetoothService(uint8_t port);
        virtual void            setHostLookup(const std::map<std::string,std::string>);
        typedef std::map<std::string, std::string> BTNameMap;

private:
        sdp_session_t *sdp_session;
        BTNameMap      hostnameToBTAddress;
};
