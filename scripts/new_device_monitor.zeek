# This script will monitor for new devices on the network via DHCP
# It uses an SQLite backed database to persist across Zeek restarts. This also means that it won't really scale well
# Alerts end up in the `notice.log` log
module NewDeviceMonitor;

export {
    redef enum Notice::Type += {
        NewDevice
    };

    redef record Notice::Info += {
		dhcp_host_name: string &log &default=""; # The host name of the orig_h
	};

    option history_expiration_interval = 30days;
    option enable_persistence = T;
}

global store: Cluster::StoreInfo;
global address_store: table[addr] of string;

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
        local key = msg$chaddr;
        local host_name = "";
        if (options?$host_name) {
            host_name = options$host_name;
        }
        when (local exists = Broker::exists(store$store, key)) {
                local bool_exists = (exists$result as bool);
                if (!bool_exists) {
                        NOTICE([$note=NewDevice,
                                $conn=c,
                                $suppress_for=1msec,
                                $msg="New Device: " + msg$chaddr + " with name " + host_name]);
                }
                when (local put_result = Broker::put(store$store, key, T, NewDeviceMonitor::history_expiration_interval)) {
                } timeout 5sec { Cluster::log("Timeout when writing MAC to store"); }
        } timeout 5sec { Cluster::log("Timeout when trying to see if a MAC exists"); }
}

event DHCP::log_dhcp(req: DHCP::Info) {
    local host_name = "";
    if (req?$host_name) {
        host_name = req$host_name;
    }
    if (req?$assigned_addr) {
        address_store[req$assigned_addr] = host_name;
    } else if (req?$requested_addr) {
        address_store[req$requested_addr] = host_name;
    }
}

# Add the host name to notices
hook Notice::notice(n: Notice::Info) {
    if (n?$id) {
        if (n$id$orig_h in address_store) {
            n$dhcp_host_name = address_store[n$id$orig_h];
        }
    }
}

event zeek_init() {
    store = Cluster::create_store("new_device_monitoring", NewDeviceMonitor::enable_persistence);
}

event zeek_done() {
    print address_store;
}