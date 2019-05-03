/*
 * ArchBluetoothNetWin.cpp
 *
 *  Created on: Feb 19, 2011
 *      Author: I821933
 */
#include <InitGuid.h>
#include <WinSock2.h>
/* #include <ws2bth.h> */
#include <regex>
#include "ArchBluetoothNetWin.h"
#include "base/Log.h"


//static SOCKET (PASCAL FAR *accept_winsock)(SOCKET s, struct sockaddr FAR *addr, int FAR *addrlen);
//static int (PASCAL FAR *bind_winsock)(SOCKET s, const struct sockaddr FAR *addr, int namelen);
//static int (PASCAL FAR *close_winsock)(SOCKET s);
//static int (PASCAL FAR *connect_winsock)(SOCKET s, const struct sockaddr FAR *name, int namelen);
//static int (PASCAL FAR *gethostname_winsock)(char FAR * name, int namelen);
//static int (PASCAL FAR *getsockerror_winsock)(void);
//static int (PASCAL FAR *getsockopt_winsock)(SOCKET s, int level, int optname, void FAR * optval, int FAR *optlen);
//static u_short (PASCAL FAR *htons_winsock)(u_short v);
//static char FAR * (PASCAL FAR *inet_ntoa_winsock)(struct in_addr in);
//static unsigned long (PASCAL FAR *inet_addr_winsock)(const char FAR * cp);
//static int (PASCAL FAR *ioctl_winsock)(SOCKET s, int cmd, void FAR * data);
//static int (PASCAL FAR *listen_winsock)(SOCKET s, int backlog);
//static u_short (PASCAL FAR *ntohs_winsock)(u_short v);
//static int (PASCAL FAR *recv_winsock)(SOCKET s, void FAR * buf, int len, int flags);
//static int (PASCAL FAR *select_winsock)(int nfds, fd_set FAR *readfds, fd_set FAR *writefds, fd_set FAR *exceptfds, const struct timeval FAR *timeout);
//static int (PASCAL FAR *send_winsock)(SOCKET s, const void FAR * buf, int len, int flags);
//static int (PASCAL FAR *setsockopt_winsock)(SOCKET s, int level, int optname, const void FAR * optval, int optlen);
//static int (PASCAL FAR *shutdown_winsock)(SOCKET s, int how);
//static SOCKET (PASCAL FAR *socket_winsock)(int af, int type, int protocol);
//static struct hostent FAR * (PASCAL FAR *gethostbyaddr_winsock)(const char FAR * addr, int len, int type);
//static struct hostent FAR * (PASCAL FAR *gethostbyname_winsock)(const char FAR * name);
//static int (PASCAL FAR *WSACleanup_winsock)(void);
//static int (PASCAL FAR *WSAFDIsSet_winsock)(SOCKET, fd_set FAR * fdset);
//static WSAEVENT (PASCAL FAR *WSACreateEvent_winsock)(void);
//static BOOL (PASCAL FAR *WSACloseEvent_winsock)(WSAEVENT);
//static BOOL (PASCAL FAR *WSASetEvent_winsock)(WSAEVENT);
//static BOOL (PASCAL FAR *WSAResetEvent_winsock)(WSAEVENT);
//static int (PASCAL FAR *WSAEventSelect_winsock)(SOCKET, WSAEVENT, long);
//static DWORD (PASCAL FAR *WSAWaitForMultipleEvents_winsock)(DWORD, const WSAEVENT FAR*, BOOL, DWORD, BOOL);
//static int (PASCAL FAR *WSAEnumNetworkEvents_winsock)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);

DEFINE_GUID(BLUE_SYNERGY_UUID, 0x891e7352, 0xdf82, 0x48b5, 0xba, 0x6c, 0xc1, 0x75, 0x2b, 0x6a, 0xc4, 0x2e);
DEFINE_GUID(BLUE_SYNERGY_CLASS_UUID, 0x00003333, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

ArchBluetoothNetWin::ArchBluetoothNetWin()
{
	// Nothing to do - calling base constructor
}

ArchBluetoothNetWin::~ArchBluetoothNetWin()
{
	// Nothing to do - calling base destructor
}

ArchSocket
ArchBluetoothNetWin::newSocket(EAddressFamily family, ESocketType type)
{
	LOG((CLOG_INFO "Starting bluetooth socket service."));

	SOCKET fd = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
	if (fd == INVALID_SOCKET) {
		throwError(WSAGetLastError());
	}
	try {
		setBlockingOnSocket(fd, false);
	}
	catch (...) {
		closesocket(fd);
		throw;
	}

	LOG((CLOG_INFO "Finished creating socket."));

	// allocate socket object
    ArchSocketImpl* socket = new ArchSocketImpl;
	socket->m_socket        = fd;
	socket->m_refCount      = 1;
	socket->m_event         = WSACreateEvent();
	socket->m_pollWrite     = true;

	LOG((CLOG_INFO "Finished Starting bluetooth socket service."));

	return socket;
}

void
ArchBluetoothNetWin::bindSocket(ArchSocket s, ArchNetAddress addr)
{
    LOG((CLOG_INFO "ArchBluetoothNetWin.bindSocket..."));

	assert(s    != NULL);
	assert(addr != NULL);

	// Bind socket
	SOCKADDR_BTH serverAddr = { 0 };
	serverAddr.addressFamily = AF_BTH;
	serverAddr.btAddr = 0;
	serverAddr.port = BT_PORT_ANY;

	if (bind(s->m_socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		throwError(WSAGetLastError());
	}
    LOG((CLOG_INFO "finished ArchBluetoothNetWin.bindSocket."));
}

void
ArchBluetoothNetWin::listenOnSocket(ArchSocket s) {
	LOG((CLOG_INFO "listenOnSocket... calling super"));
	//CArchNetworkWinsock::listenOnSocket(s);
	if (listen(s->m_socket, 3) == SOCKET_ERROR) {
		int lastError = WSAGetLastError();
		LOG((CLOG_ERR "listenOnSocket... error code - $d",lastError));
		throwError(lastError);
	}
	LOG((CLOG_INFO "finished listenOnSocket... called super"));

	// Register Service
	SOCKADDR_BTH bthAddr = { 0 };
	int bthAddr_len = sizeof(bthAddr);
	if(SOCKET_ERROR == getsockname(s->m_socket, (SOCKADDR*)&bthAddr, &bthAddr_len)) {
		// TODO : handle this error condition properly
	    ExitProcess(2);
	}
	
	registerBluetoothService(bthAddr);
}

void
ArchBluetoothNetWin::registerBluetoothService(SOCKADDR_BTH addr) {
	LOG((CLOG_INFO "starting bluetooth registration..."));
	CSADDR_INFO sockInfo;
    sockInfo.iProtocol = BTHPROTO_RFCOMM;
    sockInfo.iSocketType = SOCK_STREAM;
    sockInfo.LocalAddr.lpSockaddr = (LPSOCKADDR) &addr;
    sockInfo.LocalAddr.iSockaddrLength = sizeof(addr);
    sockInfo.RemoteAddr.lpSockaddr = (LPSOCKADDR) &addr;
    sockInfo.RemoteAddr.iSockaddrLength = sizeof(addr);

    WSAQUERYSET svcInfo = { 0 };
    svcInfo.dwSize = sizeof(svcInfo);
    svcInfo.dwNameSpace = NS_BTH;
    svcInfo.lpszServiceInstanceName = "Blue-Synergy";
    svcInfo.lpszComment = "Blue Synergy Software KVM Service";
    svcInfo.lpServiceClassId = (LPGUID) &BLUE_SYNERGY_CLASS_UUID;
    svcInfo.dwNumberOfCsAddrs = 1;
    svcInfo.lpcsaBuffer = &sockInfo;

    if( SOCKET_ERROR == WSASetService( &svcInfo, RNRSERVICE_REGISTER, 0 ) ) {
		LOG((CLOG_INFO "hit an error in bluetooth registration."));
		// TODO : handle this error condition properly
		ExitProcess(2);
    }
	LOG((CLOG_INFO "finished bluetooth registration."));
}

ArchSocket
ArchBluetoothNetWin::acceptSocket(ArchSocket s, ArchNetAddress* addr)
{
    LOG((CLOG_INFO "ArchBluetoothNetWin.acceptSocket..."));
	assert(s != NULL);

	// create new socket and temporary address
    ArchSocketImpl* socket = new ArchSocketImpl;
    ArchNetAddress tmp = ArchNetAddressImpl::alloc(sizeof(struct sockaddr));

	////////////////////////////////
	// Bluetooth specific stuff
	SOCKADDR_BTH rem_addr = { 0 };
	int rem_len = sizeof(rem_addr);
	////////////////////////////////

	// accept on socket
	SOCKET fd = accept(s->m_socket, (struct sockaddr *)&rem_addr, &rem_len);
	//char message [512];
	//sprintf(message, "Accepted connection from : %04x%08x to channel $d\n", GET_NAP(rem_addr.btAddr), GET_SAP(rem_addr.btAddr), rem_addr.port);
	//LOG((CLOG_INFO "%s",message ));
	LOG((CLOG_INFO "Accepted connection from : %04x%08x to channel %d\n", GET_NAP(rem_addr.btAddr), GET_SAP(rem_addr.btAddr), rem_addr.port));
	if (fd == INVALID_SOCKET) {
		int err = WSAGetLastError();
		delete socket;
		free(tmp);
		*addr = NULL;
		if (err == WSAEWOULDBLOCK) {
			return NULL;
		}
		throwError(err);
	}

	try {
		setBlockingOnSocket(fd, false);
	}
	catch (...) {
		closesocket(fd);
		delete socket;
		free(tmp);
		*addr = NULL;
		throw;
	}

	// initialize socket
	socket->m_socket    = fd;
	socket->m_refCount  = 1;
	socket->m_event     = WSACreateEvent();
	socket->m_pollWrite = true;

	// copy address if requested
	if (addr != NULL) {
		tmp->m_len = rem_len;
		memcpy(TYPED_ADDR(void, tmp), &rem_addr, rem_len);
		*addr = ARCH->copyAddr(tmp);
	}

	free(tmp);
	return socket;
}

bool
ArchBluetoothNetWin::connectSocket(ArchSocket s, ArchNetAddress addr)
{
    LOG((CLOG_NOTE "Starting ArchBluetoothNetWin.connectSocket...."));

	assert(s    != NULL);
	assert(addr != NULL);

	LOG((CLOG_NOTE "    creating new address"));
	//////////////////////////////////////////////
	// Bluetooth specific
	std::string serverAddr = addrToString(addr);
	char server[256];
	strcpy(server, serverAddr.c_str());
	LOG((CLOG_NOTE "    Server Address: %s", server));
	SOCKADDR_BTH btaddr = { 0 };
	int btaddr_len = sizeof btaddr;
	WSAStringToAddress(server, AF_BTH, NULL, (LPSOCKADDR) & btaddr, & btaddr_len);
	btaddr.addressFamily = AF_BTH;
	//btaddr.port = 1;
	btaddr.port = findServicePort(server);
	LOG((CLOG_NOTE "    Server Port: %d", btaddr.port));
	//////////////////////////////////////////////
	LOG((CLOG_NOTE "    finished creating new address"));

	if (connect(s->m_socket, (struct sockaddr *) &btaddr, sizeof(btaddr)) == SOCKET_ERROR) {
		LOG((CLOG_WARN "    Problem with connecting to socket."));
		if (WSAGetLastError() == WSAEISCONN) {
			LOG((CLOG_WARN "    WSAEISCONN."));
			return true;
		}
		if (WSAGetLastError() == WSAEWOULDBLOCK) {
			LOG((CLOG_WARN "    WSAEWOULDBLOCK."));
			return false;
		}

		char Message[1024];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
		                  FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, WSAGetLastError(),
		                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		                  (LPSTR) Message, 1024, NULL);

		LOG((CLOG_WARN "    WSAGetLastError: %s", Message));
		throwError(WSAGetLastError());
	}

    LOG((CLOG_NOTE "finished ArchBluetoothNetWin.connectSocket...."));
	return true;
}

ArchNetAddress
ArchBluetoothNetWin::newAnyAddr(EAddressFamily family)
{
    LOG((CLOG_INFO "ArchBluetoothNetWin.newAnyAddr..."));

	// allocate address
    ArchNetAddressImpl* addr = NULL;

	// fill it in - assume kBLUETOOTH family
    addr = ArchNetAddressImpl::alloc(sizeof(SOCKADDR_BTH));
	SOCKADDR_BTH* BAddr  = TYPED_ADDR(SOCKADDR_BTH, addr);
	BAddr->addressFamily = AF_BTH;
	BAddr->port          = BT_PORT_ANY;
	BAddr->btAddr        = 0;
	addr->m_len          = sizeof(SOCKADDR_BTH);

    LOG((CLOG_INFO "finished ArchBluetoothNetWin.newAnyAddr."));

	return addr;
}

bool
ArchBluetoothNetWin::setNoDelayOnSocket(ArchSocket s, bool noDelay)
{
	return true;
}

ArchNetAddress
ArchBluetoothNetWin::nameToAddr(const std::string& name)
{
	// allocate address
    ArchNetAddressImpl* addr = ArchNetAddressImpl::alloc(sizeof(SOCKADDR_BTH));

	SOCKADDR_BTH inaddr;
	memset(&inaddr, 0, sizeof(inaddr));

	char dest[128];
	bool found = false;
    for (std::map<std::string,std::string>::iterator it=hostnameToBTAddress.begin(); it!=hostnameToBTAddress.end(); ++it) {
        std::string host = it->first;
        std::string btAddress = it->second;
		if (name.compare(host) == 0) {
            LOG((CLOG_INFO "    Got address %s.", btAddress.c_str()));
			strcpy(dest, btAddress.c_str());
			found = true;
			break;
		}
	}

	if (found == false) {
		std::string hostname = findDevice(name);
		strcpy(dest, hostname.c_str());
	}

	int inaddr_len = sizeof(inaddr);
	WSAStringToAddress(dest, AF_BTH, NULL, (LPSOCKADDR) & inaddr, & inaddr_len);

	addr->m_len = sizeof(SOCKADDR_BTH);
	inaddr.addressFamily = AF_BTH;
	inaddr.port = 1;
	memcpy(&addr->m_addr, &inaddr, addr->m_len);

	return addr;
}

std::string
ArchBluetoothNetWin::addrToName(ArchNetAddress addr)
{
    LOG((CLOG_INFO "    ArchBluetoothNetWin.addrToName - doing nothing."));

	return "NA";
}

IArchNetwork::EAddressFamily
ArchBluetoothNetWin::getAddrFamily(ArchNetAddress addr)
{
	assert(addr != NULL);

	return kBLUETOOTH;
}

std::string
ArchBluetoothNetWin::addrToString(ArchNetAddress addr)
{
	assert(addr != NULL);

	SOCKADDR_BTH *baddr = reinterpret_cast<SOCKADDR_BTH*>(&addr->m_addr);
	ULONG nap = GET_NAP(baddr->btAddr);
	ULONG sap = GET_SAP(baddr->btAddr);

	char napStr[6];
	sprintf(napStr, "%04lx", nap);
	char sapStr[10];
	sprintf(sapStr, "%08lx", sap);
	int first, second, third, fourth, fifth, sixth;
	sscanf(napStr, "%02x%02x", &first, &second);
	sscanf(sapStr, "%02x%02x%02x%02x", &third, &fourth, &fifth, &sixth);

	char bluetoothAddress[18];
	sprintf(bluetoothAddress, "%02x:%02x:%02x:%02x:%02x:%02x", first, second, third, fourth, fifth, sixth);

	return bluetoothAddress;
}

void
ArchBluetoothNetWin::setAddrPort(ArchNetAddress addr, int port)
{
	assert(addr != NULL);
	
	SOCKADDR_BTH *btAddr = reinterpret_cast<SOCKADDR_BTH*>(&addr->m_addr);
	btAddr->port = port;
}

int
ArchBluetoothNetWin::getAddrPort(ArchNetAddress addr)
{
	assert(addr != NULL);

	SOCKADDR_BTH *btAddr = reinterpret_cast<SOCKADDR_BTH*>(&addr->m_addr);
	return btAddr->port;
}

bool
ArchBluetoothNetWin::isAnyAddr(ArchNetAddress addr)
{
	assert(addr != NULL);

	SOCKADDR_BTH *bAddr = reinterpret_cast<SOCKADDR_BTH*>(&addr->m_addr);

	return (addr->m_len == sizeof(SOCKADDR_BTH) && bAddr->btAddr == BTH_ADDR_NULL);
}

int
ArchBluetoothNetWin::findServicePort(const char *addr) {
	int port = 1;
    HANDLE h;
	WSAQUERYSET *qs;
	DWORD flags = 0;
	DWORD qs_len;
	bool done;

    qs_len = sizeof(WSAQUERYSET);
    qs = (WSAQUERYSET*) malloc( qs_len );
    ZeroMemory( qs, qs_len );
    qs->dwSize = sizeof(WSAQUERYSET);
	qs->lpServiceClassId = (LPGUID)&BLUE_SYNERGY_CLASS_UUID;
    qs->dwNameSpace = NS_BTH;
    qs->dwNumberOfCsAddrs = 0;
    qs->lpszContext = (LPSTR) addr;

    flags = LUP_FLUSHCACHE | LUP_RETURN_ALL;

    if( SOCKET_ERROR == WSALookupServiceBegin( qs, flags, &h )) {
        ExitProcess(2);
    }

    done = false;
    while ( ! done ) {
        if( SOCKET_ERROR == WSALookupServiceNext(h, flags, &qs_len, qs) ) {
            int error = WSAGetLastError();
            if( error == WSAEFAULT ) {
                free(qs);
                qs = (WSAQUERYSET*) malloc( qs_len );
            } else if (error == WSA_E_NO_MORE ) {
                done = true;
				LOG((CLOG_NOTE "    Did not find service, setting port to 1"));
            } else {
                ExitProcess(2);
            }
        } else {
			LOG((CLOG_NOTE "    Found Service Name: %s", qs->lpszServiceInstanceName));
            SOCKADDR_BTH *sa = (SOCKADDR_BTH*)qs->lpcsaBuffer->RemoteAddr.lpSockaddr;
            port = sa->port;
			LOG((CLOG_NOTE "    Found Port: %d", port));
			done = true;
        }
    }
    free(qs);
   
	WSALookupServiceEnd( h );

    return port;
}

//std::string wstrtostr(const std::wstring &wstr)
//{
//    std::string strTo;
//    char *szTo = new char[wstr.length() + 1];
//    szTo[wstr.size()] = '\0';
//    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
//    strTo = szTo;
//    delete[] szTo;
//    return strTo;
//}

std::string ArchBluetoothNetWin::findDevice(const std::string& serverName) {
	LOG((CLOG_INFO "Entering findDevice...."));
	// setup windows sockets
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD( 2, 0 );
    if( WSAStartup( wVersionRequested, &wsaData ) != 0 ) {
		LOG((CLOG_WARN "Failure in Windows Sockets!"));
        ExitProcess(2);
    }
    // prepare the inquiry data structure
    DWORD qs_len = sizeof( WSAQUERYSET );
    WSAQUERYSET *qs = (WSAQUERYSET*) malloc( qs_len );
    ZeroMemory( qs, qs_len );
    qs->dwSize = sizeof(WSAQUERYSET);
    qs->dwNameSpace = NS_BTH;
    DWORD flags = LUP_CONTAINERS;
    flags |= LUP_FLUSHCACHE | LUP_RETURN_NAME | LUP_RETURN_ADDR;
    HANDLE h;
    // start the device inquiry
    if( SOCKET_ERROR == WSALookupServiceBegin( qs, flags, &h )) {
		LOG((CLOG_WARN "Failure in Service Lookup Begin!"));
        ExitProcess(2);
    }	LOG((CLOG_INFO "Got results, about to loop"));
    // iterate through the inquiry results
    bool done = false;
	std::string serverBTA;
    while(! done) {
        if(NO_ERROR == WSALookupServiceNext(h, flags, &qs_len, qs)) {
            char buf[80] = {0};
			LPWSTR lpBuff;
            SOCKADDR_BTH *sa = (SOCKADDR_BTH*)qs->lpcsaBuffer->RemoteAddr.lpSockaddr;
            BTH_ADDR result = sa->btAddr;
            DWORD bufsize = sizeof(buf);
            WSAAddressToString((LPSOCKADDR)sa, sizeof(SOCKADDR_BTH), NULL, (LPSTR) buf, &bufsize);			
			// Get friendly name, should be the hostname that client is using
			std::string hostname = std::string(qs->lpszServiceInstanceName);
			LOG((CLOG_NOTE "    Return Name: %s", hostname));
			if (serverName.compare(hostname) == 0) {
				ULONG nap = GET_NAP(sa->btAddr);
				ULONG sap = GET_SAP(sa->btAddr);

				char napStr[6];
				sprintf(napStr, "%04lx", nap);
				char sapStr[10];
				sprintf(sapStr, "%08lx", sap);
				int first, second, third, fourth, fifth, sixth;
				sscanf(napStr, "%02x%02x", &first, &second);
				sscanf(sapStr, "%02x%02x%02x%02x", &third, &fourth, &fifth, &sixth);

				char bluetoothAddress[18];
				sprintf(bluetoothAddress, "%02x:%02x:%02x:%02x:%02x:%02x", first, second, third, fourth, fifth, sixth);
				LOG((CLOG_NOTE "    Device: %s", bluetoothAddress));
				serverBTA = std::string(bluetoothAddress);
			}
        } else {
            int error = WSAGetLastError();
            if( error == WSAEFAULT ) {
                free( qs );
                qs = (WSAQUERYSET*) malloc( qs_len );
            } else if( error == WSA_E_NO_MORE ) {
                printf("inquiry complete\n");
                done = true;
            } else {
                printf("uh oh.  error code %d\n", error);
                done = true;
            }
        }
    }
    WSALookupServiceEnd( h );
    free( qs );
    WSACleanup();

	LOG((CLOG_NOTE "Finished findDevice...."));
    return serverBTA;
}

void ArchBluetoothNetWin::setHostLookup(const std::map<std::string,std::string> configMap) {
	hostnameToBTAddress = configMap;
}
