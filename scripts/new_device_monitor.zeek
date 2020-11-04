# This script will monitor for new devices on the network via DHCP
# It uses an SQLite backed database to persist across Zeek restarts. This also means that it won't really scale well
# Alerts end up in the `notice.log` log
module NewDeviceMonitor;

export {
    redef enum Notice::Type += {
        NewDevice
    };

    option history_expiration_interval = 30days;
    option enable_persistence = T;
}

global store: Cluster::StoreInfo;

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
        local key = msg$chaddr;
        when (local exists = Broker::exists(store$store, key)) {
                local bool_exists = (exists$result as bool);
                if (!bool_exists) {
                    local host_name = "";
                    if (options?$host_name) {
                        host_name = options$host_name;
                    }
                        NOTICE([$note=NewDevice,
                                $conn=c,
                                $suppress_for=1msec,
                                $msg="New Device: " + msg$chaddr + " with name " + host_name]);
                }
                when (local put_result = Broker::put(store$store, key, T, NewDeviceMonitor::history_expiration_interval)) {
                } timeout 5sec { Cluster::log("Timeout when writing MAC to store"); }
        } timeout 5sec { Cluster::log("Timeout when trying to see if a MAC exists"); }
}

event zeek_init() {
    store = Cluster::create_store("new_device_monitoring", NewDeviceMonitor::enable_persistence);
}
