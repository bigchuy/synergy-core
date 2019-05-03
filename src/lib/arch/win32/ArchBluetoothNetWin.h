/*
 * CArchBluetoothNetWin.h
 *
 *  Created on: Feb 19, 2011
 *      Author: I821933
 */

#pragma once

#include <ws2bth.h>

#include "arch/IArchMultithread.h"
#include "ArchNetworkWinsock.h"
#include "net/NetworkAddress.h"

#define ARCH_NETWORK ArchBluetoothNetWin

class ArchBluetoothNetWin : public ArchNetworkWinsock {

public:
    ArchBluetoothNetWin();
    virtual ~ArchBluetoothNetWin();

    virtual ArchSocket	    newSocket(EAddressFamily, ESocketType);
    virtual void		    bindSocket(ArchSocket s, ArchNetAddress addr);
    virtual ArchNetAddress	newAnyAddr(EAddressFamily);
    virtual ArchNetAddress	nameToAddr(const std::string&);
    virtual std::string		addrToName(ArchNetAddress);
    virtual std::string		addrToString(ArchNetAddress);
    virtual EAddressFamily	getAddrFamily(ArchNetAddress);
    virtual void			setAddrPort(ArchNetAddress, int port);
    virtual int				getAddrPort(ArchNetAddress);
    virtual bool			isAnyAddr(ArchNetAddress);
    virtual void		    listenOnSocket(ArchSocket);
    virtual bool            setNoDelayOnSocket(ArchSocket, bool);
    virtual bool		    connectSocket(ArchSocket, ArchNetAddress);
    virtual ArchSocket	    acceptSocket(ArchSocket s, ArchNetAddress* addr);
	virtual std::string     findDevice(const std::string& serverName);
	virtual int             findServicePort(const char *addr);
	virtual void			registerBluetoothService(SOCKADDR_BTH addr);
    virtual void            setHostLookup(std::map<std::string,std::string> configMap);

    typedef std::map<std::string, std::string> BTNameMap;

private:
	BTNameMap hostnameToBTAddress;
};
