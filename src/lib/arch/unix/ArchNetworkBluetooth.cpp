#include "ArchNetworkBluetooth.h"
#include "base/Log.h"
#include "arch/Arch.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
//#include <dbus-1.0/dbus/dbus-glib.h>
#include <errno.h>
#include <unistd.h>

// Adding a comment to see if diff works
ArchNetworkBluetooth::ArchNetworkBluetooth()
=default;

ArchNetworkBluetooth::~ArchNetworkBluetooth()
{
        ARCH->closeMutex(m_mutex);
}

void
ArchNetworkBluetooth::init()
{
    // create mutex to make some calls thread safe
    m_mutex = ARCH->newMutex();
    sdp_session = NULL;
}

ArchSocket
ArchNetworkBluetooth::newSocket(EAddressFamily family, ESocketType type)
{
        LOG((CLOG_INFO "Starting bluetooth socket service."));
        // disregard family and type since they are surely not Bluetooth

        // create socket
        int fd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        LOG((CLOG_INFO "socket # - '%d'",fd));
        if (fd == -1) {
                throwError(errno);
        }
        try {
                setBlockingOnSocket(fd, false);
        }
        catch (...) {
                close(fd);
                throw;
        }

        LOG((CLOG_INFO "Finished creating socket."));

//	if(family == kBLUETOOTH) {
//		int opt = 0;
//		opt |= RFCOMM_LM_AUTH;
//		opt |= RFCOMM_LM_ENCRYPT;
//		opt |= RFCOMM_LM_SECURE;
//
//		setsockopt(fd, SOL_RFCOMM, RFCOMM_LM, &opt, sizeof(opt));
//	}

        // allocate socket object
        ArchSocketImpl* newSocket = new ArchSocketImpl;
        newSocket->m_fd            = fd;
        newSocket->m_refCount      = 1;

        LOG((CLOG_INFO "Finished Starting bluetooth socket service."));

        return newSocket;
}

void
ArchNetworkBluetooth::bindSocket(ArchSocket s, ArchNetAddress addr)
{
        LOG((CLOG_INFO "ArchNetworkBluetooth.bindSocket..."));
        assert(s    != NULL);
        assert(addr != NULL);

//	setAddrPort(btaddr, 1);
        struct sockaddr_rc loc_addr = {0};
        loc_addr.rc_family = AF_BLUETOOTH;
        loc_addr.rc_bdaddr = *BDADDR_ANY;
        // Channel needs to be set to zero so that the port(channel) is dynamically assigned
        loc_addr.rc_channel = (uint8_t) 0;

        if (bind(s->m_fd, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) == -1) {
                throwError(errno);
        }

        LOG((CLOG_INFO "finished ArchNetworkBluetooth.bindSocket."));
}

ArchNetAddress
ArchNetworkBluetooth::newAnyAddr(EAddressFamily family)
{
        LOG((CLOG_INFO "ArchNetworkBluetooth.newAnyAddr..."));

        // allocate address
        ArchNetAddressImpl* addr = new ArchNetAddressImpl;

        // fill it in - assume kBLUETOOTH family
        struct sockaddr_rc* BAddr = reinterpret_cast<struct sockaddr_rc*>(&addr->m_addr);
        BAddr->rc_family          = AF_BLUETOOTH;
        BAddr->rc_bdaddr	      = *BDADDR_ANY;
        BAddr->rc_channel	      = (uint8_t) 1;
        addr->m_len               = sizeof(struct sockaddr_rc);

        LOG((CLOG_INFO "finished ArchNetworkBluetooth.newAnyAddr."));

        return addr;
}

ArchNetAddress
ArchNetworkBluetooth::nameToAddr(const std::string& name)
{
        LOG((CLOG_INFO "Resolving address for - %s.", name.c_str()));
        // allocate address
        ArchNetAddressImpl* addr = new ArchNetAddressImpl;

        struct sockaddr_rc inaddr;
        memset(&inaddr, 0, sizeof(inaddr));

        // check if it is a bdaddr string
//	if(bachk(name.c_str()))
//		str2ba(BLUEZ->lookupAddress(name).c_str(), &inaddr.rc_bdaddr);
//	else
//	    str2ba(name.c_str(), &inaddr.rc_bdaddr);

        char dest[128];
        bool found = false;

        for (std::map<std::string,std::string>::iterator it=hostnameToBTAddress.begin(); it!=hostnameToBTAddress.end(); ++it) {
                std::string host = it->first;
                std::string btAddress = it->second;
                if (name.compare(host) == 0) {
                        LOG((CLOG_INFO "    Got address %s.", btAddress.c_str()));
                        strcpy(dest, btAddress.c_str());
                        // April 2nd : str2ba(btAddress.c_str(), &inaddr.rc_bdaddr);
                        found = true;
                        break;
                }
        }

//	if (name.compare("wopr") == 0) {
//		str2ba("00:02:72:1E:BC:1A", &inaddr.rc_bdaddr); // wopr-0
//	} else if (name.compare("DALN00498446A") == 0) {
//		str2ba("00:02:72:1E:BB:81", &inaddr.rc_bdaddr); //lilly-0
//	} else if (name.compare("AGSN00452138A") == 0) {
//		str2ba("00:02:72:1F:59:6C", &inaddr.rc_bdaddr); //lilly-0
//	} else {
//		// do nothing
//	}

        // April 2nd
        if (found == false) {
            std::string hostname = findDevice(name);
            strcpy(dest, hostname.c_str());
        }

        str2ba(dest, &inaddr.rc_bdaddr);
        //

        addr->m_len = sizeof(struct sockaddr_rc);
        inaddr.rc_family = AF_BLUETOOTH;
        inaddr.rc_channel = (uint8_t) 1;
        memcpy(&addr->m_addr, &inaddr, addr->m_len);

        return addr;
}

std::string
ArchNetworkBluetooth::findDevice(const std::string& serverName) {
    inquiry_info *devices = NULL;
    int max_rsp, num_rsp;
    int adapter_id, sock, len, flags;
    int i;
    char addr[19] = { 0 };
    char name[248] = { 0 };

    std::string serverBTA;

    adapter_id = hci_get_route(NULL);
    sock = hci_open_dev( adapter_id );
    if (adapter_id < 0 || sock < 0) {
        LOG((CLOG_ERR "Problem finding device.- %s", serverName));
    } else {
        len  = 8;
        max_rsp = 255;
        flags = IREQ_CACHE_FLUSH;
        devices = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));

        num_rsp = hci_inquiry(adapter_id, len, max_rsp, NULL, &devices, flags);
        if( num_rsp < 0 ) LOG((CLOG_ERR "Device not discovered.- %s", serverName));

        for (i = 0; i < num_rsp; i++) {
            ba2str(&(devices+i)->bdaddr, addr);
            memset(name, 0, sizeof(name));
            if (0 != hci_read_remote_name(sock, &(devices+i)->bdaddr, sizeof(name), name, 0)) {
                strcpy(name, "[unknown]");
            }
            printf("%s  %s\n", addr, name);
            if (serverName.compare(name) == 0) {
                serverBTA = std::string(addr);
            }
        }

        free( devices );
        close( sock );
    }

    return serverBTA;
}

std::string
ArchNetworkBluetooth::addrToName(ArchNetAddress addr)
{
        assert(addr != NULL);

        struct sockaddr_rc *baddr = reinterpret_cast<sockaddr_rc*>(&addr->m_addr);
        char cstr[18] = "00:00:00:00:00:00";
        ba2str(&baddr->rc_bdaddr, cstr);
        std::string s = cstr;

        LOG((CLOG_INFO "Resolving name for - %s.", s.c_str()));

        for (std::map<std::string,std::string>::iterator it=hostnameToBTAddress.begin(); it!=hostnameToBTAddress.end(); ++it) {
                std::string host = it->first;
                std::string btAddress = it->second;
                if (s.compare(btAddress) == 0) {
                        s = host;
                        break;
                }
        }

//	if (s.compare("00:02:72:1E:BC:1A") == 0) {
//		s = "wopr";
//	} else if (s.compare("00:02:72:1E:BB:81") == 0){
//		s = "DALN00484568A";
//	} else if (s.compare("00:02:72:1F:59:6C") == 0){
//		s = "AGSN00452138A";
//	}

        LOG((CLOG_INFO "    Got name %s.", s.c_str()));

        return s;
}

std::string
ArchNetworkBluetooth::addrToString(ArchNetAddress addr)
{
        assert(addr != NULL);

        struct sockaddr_rc *baddr = reinterpret_cast<sockaddr_rc*>(&addr->m_addr);
        char cstr[18] = "00:00:00:00:00:00";
        ba2str(&baddr->rc_bdaddr, cstr);
        std::string s = cstr;
        LOG((CLOG_INFO "Address to String - %s.", s.c_str()));
        return s;
}

IArchNetwork::EAddressFamily
ArchNetworkBluetooth::getAddrFamily(ArchNetAddress addr)
{
        assert(addr != NULL);

        return kBLUETOOTH;
}

void
ArchNetworkBluetooth::setAddrPort(ArchNetAddress addr, int port)
{
        assert(addr != NULL);

        struct sockaddr_rc* ipAddr = reinterpret_cast<struct sockaddr_rc*>(&addr->m_addr);
        ipAddr->rc_channel = (uint8_t) port;
}

int
ArchNetworkBluetooth::getAddrPort(ArchNetAddress addr)
{
        assert(addr != NULL);

        struct sockaddr_rc* ipAddr = reinterpret_cast<struct sockaddr_rc*>(&addr->m_addr);
        return ipAddr->rc_channel;
}

bool
ArchNetworkBluetooth::isAnyAddr(ArchNetAddress addr)
{
        assert(addr != NULL);

        struct sockaddr_rc* BAddr = reinterpret_cast<struct sockaddr_rc*>(&addr->m_addr);
        char *a, *b;
        int n;
        a = (char*)&BAddr->rc_bdaddr;
        b = (char*)(&(bdaddr_t){{0,0,0,0,0,0}});
        for(n=0;n<6;n++) {
                if(a[n]!=b[n]) return false;
        }
        return (addr->m_len == sizeof(struct sockaddr_rc));
}

int
ArchNetworkBluetooth::findServicePort(std::string serviceAddress) {
        int port = 1;
        int status;
        bdaddr_t target;
        uuid_t svc_uuid;
        sdp_session_t *session = 0;
        uint32_t flags = 0;
        uint32_t attrs = 0x0000ffff;
        sdp_list_t *response_list, *search_list, *attrid_list;

        // Translate address
        str2ba( serviceAddress.c_str(), &target );

        // connect to the SDP server running on the remote machine
        session = sdp_connect( BDADDR_ANY, &target, flags );
        sdp_uuid16_create( &svc_uuid, BLUE_SYNERGY_CLASS_UUID );
        search_list = sdp_list_append( 0, &svc_uuid );
        attrid_list = sdp_list_append( 0, &attrs );

        response_list = NULL;

        // Start Search
        status = sdp_service_search_attr_req( session, search_list, SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
        if( status == 0 ) {
                sdp_list_t *proto_list = NULL;
                bool found = false;

                // There should be only one Blue Synergy Server Running
                sdp_list_t *r = response_list;

                for (; r; r = r->next ) {
                        sdp_record_t *rec = (sdp_record_t*) r->data;

                        // get a list of the protocol sequences
                        if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
                                found = true;
                                // get the RFCOMM port number
                                port = sdp_get_proto_port( proto_list, RFCOMM_UUID );
                                sdp_list_free( proto_list, 0 );
                        }
                        sdp_record_free( rec );
                }
                if (!found) {
                        LOG((CLOG_WARN "Unable to locate Blue Synergy Port, setting Port to 1"));
                }
        } else {
                LOG((CLOG_ERR "Unable to locate Blue Synergy Service, setting Port to 1"));
        }

        sdp_list_free( response_list, 0 );
        sdp_list_free( search_list, 0 );
        sdp_list_free( attrid_list, 0 );

        LOG((CLOG_INFO "Blue Synergy Port - '%d'", port));
        return port;
}

void
ArchNetworkBluetooth::listenOnSocket(ArchSocket s) {
        LOG((CLOG_INFO "listenOnSocket... calling super"));
        ArchNetworkBSD::listenOnSocket(s);
        LOG((CLOG_INFO "finished listenOnSocket... called super"));

        struct sockaddr address;
        memset(&address, 0, sizeof(address));
        socklen_t addrSize = sizeof(address);
        getsockname(s->m_fd, &address, &addrSize);
        struct sockaddr_rc* btAddr = reinterpret_cast<struct sockaddr_rc*>(&address);
        uint8_t port = btAddr->rc_channel;
        registerBluetoothService(port);
}

ArchSocket
ArchNetworkBluetooth::acceptSocket(ArchSocket s, ArchNetAddress* addr)
{
        LOG((CLOG_INFO "ArchNetworkBluetooth.acceptSocket..."));
        assert(s != NULL);

        // if user passed NULL in addr then use scratch space
        ArchNetAddress dummy;
        if (addr == NULL) {
                addr = &dummy;
        }

        // create new socket and address
        ArchSocketImpl* newSocket = new ArchSocketImpl;
        *addr                      = new ArchNetAddressImpl;

        // accept on socket
        struct sockaddr_rc rem_addr = { 0 };
        socklen_t rem_len = sizeof(rem_addr);
//	ACCEPT_TYPE_ARG3 len = (ACCEPT_TYPE_ARG3)((*addr)->m_len);
//	int fd = accept(s->m_fd, &(*addr)->m_addr, &len);
        int fd = accept(s->m_fd, (struct sockaddr *)&rem_addr, &rem_len);
//	(*addr)->m_len = (socklen_t)len;
        if (fd == -1) {
                int err = errno;
                delete newSocket;
                delete *addr;
                *addr = NULL;
                if (err == EAGAIN) {
                        return NULL;
                }
                throwError(err);
        }

        try {
                setBlockingOnSocket(fd, false);
        }
        catch (...) {
                close(fd);
                delete newSocket;
                delete *addr;
                *addr = NULL;
                throw;
        }

        // initialize socket
        newSocket->m_fd       = fd;
        newSocket->m_refCount = 1;

        // discard address if not requested
        if (addr == &dummy) {
                ARCH->closeAddr(dummy);
        }

        LOG((CLOG_INFO "finished ArchNetworkBluetooth.acceptSocket."));

        return newSocket;
}

bool
ArchNetworkBluetooth::setNoDelayOnSocket(ArchSocket s, bool noDelay)
{
        return true;
}

bool
ArchNetworkBluetooth::connectSocket(ArchSocket s, ArchNetAddress addr)
{
        LOG((CLOG_NOTE "Starting ArchNetworkBluetooth.connectSocket...."));

        assert(s    != NULL);
        assert(addr != NULL);

        std::string serverAddr = addrToString(addr);
        char server[256];
        strcpy(server, serverAddr.c_str());
        LOG((CLOG_NOTE "    creating new address"));
        LOG((CLOG_NOTE "    server address - '%s'", server));
        //const char *cstr = serverAddr.c_str();
        struct sockaddr_rc btaddr = { 0 };
        btaddr.rc_family = AF_BLUETOOTH;
        int port = findServicePort(serverAddr);
        LOG((CLOG_NOTE "    port number - '%d'", port));
        btaddr.rc_channel = port;
        str2ba(server, &btaddr.rc_bdaddr);
        LOG((CLOG_NOTE "    finished creating new address"));
        LOG((CLOG_NOTE "    socket # - '%d'",s->m_fd));
        if (connect(s->m_fd, (struct sockaddr *)&btaddr, sizeof(btaddr)) == -1) {
                LOG((CLOG_WARN "    Problem with connecting to socket.- %s", strerror(errno)));
                if (errno == EISCONN) {
                        return true;
                }
                if (errno == EINPROGRESS) {
                        LOG((CLOG_WARN "    EINPROGRESS"));
                        return false;
                }
                throwError(errno);
        }
        LOG((CLOG_NOTE "Finished ArchNetworkBluetooth::connectSocket."));
        return true;
}

void ArchNetworkBluetooth::registerBluetoothService(uint8_t portNumber) {
        LOG((CLOG_INFO "Entering Register Bluetooth Service..."));
        uint32_t service_uuid_int[] = { 0x891e7352, 0xdf8248b5, 0xba6cc175, 0x2b6ac42e };
        //uint32_t class_uuid = 0x00003333;
        //891e7352-df82-48b5-ba6c-c1752b6ac42e

        // Set the Service Attributes
    const char *service_name = "Blue-Synergy";
    const char *service_dsc = "Blue Synergy Software KVM Service";
    const char *service_prov = "FSI";

    // Initialize attributes
    uuid_t root_uuid, l2cap_uuid, rfcomm_uuid, svc_uuid, svc_class_uuid;
    sdp_list_t *l2cap_list = 0,
               *rfcomm_list = 0,
               *root_list = 0,
               *proto_list = 0,
               *access_proto_list = 0,
               *svc_class_list = 0,
               *profile_list = 0;
    // TODO : check psm usage
    sdp_data_t *channel = 0, *psm = 0;

    // Get a service record
    sdp_record_t *record = sdp_record_alloc();
LOG((CLOG_INFO "    point 1"));
    // set the general service ID
    sdp_uuid128_create( &svc_uuid, &service_uuid_int );
    //sdp_uuid128_create( &svc_uuid, BLUE_SYNERGY_UUID );
    sdp_set_service_id( record, svc_uuid );
    LOG((CLOG_INFO "    point 2"));
    // set the service class
//    sdp_uuid16_create(&svc_class_uuid, GENERIC_NETWORKING_SVCLASS_ID);
    //sdp_uuid32_create(&svc_class_uuid, class_uuid);
    sdp_uuid32_create(&svc_class_uuid, BLUE_SYNERGY_CLASS_UUID);
    svc_class_list = sdp_list_append(0, &svc_class_uuid);
//    svc_class_list = sdp_list_append(0, &svc_uuid);
    sdp_set_service_classes(record, svc_class_list);
    LOG((CLOG_INFO "    point 3"));
    // make the service record publicly browsable
    sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
    root_list = sdp_list_append(0, &root_uuid);
    sdp_set_browse_groups( record, root_list );

    // set l2cap information
    sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
    l2cap_list = sdp_list_append( 0, &l2cap_uuid );
    proto_list = sdp_list_append( 0, l2cap_list );

    // set rfcomm information
    sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
    channel = sdp_data_alloc(SDP_UINT8, &portNumber);
    rfcomm_list = sdp_list_append( 0, &rfcomm_uuid );
    sdp_list_append( rfcomm_list, channel );
    sdp_list_append( proto_list, rfcomm_list );
    LOG((CLOG_INFO "    point 4"));
    // attach protocol information to service record
    access_proto_list = sdp_list_append( 0, proto_list );
    sdp_set_access_protos( record, access_proto_list );

    // set the name, provider, and description
    sdp_set_info_attr(record, service_name, service_prov, service_dsc);

    // Register the Service
    int err = 0;
    sdp_session_t *session = 0;
    LOG((CLOG_INFO "    point 5"));
    // connect to the local SDP server, register the service record, and
    // disconnect
    session = sdp_connect( BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY );
    err = sdp_record_register(session, record, 0);
    LOG((CLOG_INFO "    point 6"));
    // cleanup
    sdp_data_free( channel );
    sdp_list_free( l2cap_list, 0 );
    sdp_list_free( rfcomm_list, 0 );
    sdp_list_free( root_list, 0 );
    sdp_list_free( access_proto_list, 0 );
    sdp_list_free( svc_class_list, 0 );
    sdp_list_free( proto_list, 0 );

    LOG((CLOG_INFO "Finished Registering Bluetooth Service."));
}

void ArchNetworkBluetooth::setHostLookup(const std::map<std::string,std::string> configMap) {
        hostnameToBTAddress = configMap;
}
