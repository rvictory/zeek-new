# This script will monitor for new orig_h->resp_h pairs on your network
# It uses an SQLite backed database to persist across Zeek restarts. This also means that it won't really scale well
# Alerts end up in the `notice.log` log
module NewConnectionMonitor;

export {
    redef enum Notice::Type += {
        NewOrigRespPair
    };

    option history_expiration_interval = 30days;
    option enable_persistence = T;
}

global store: Cluster::StoreInfo;

event connection_state_remove(c: connection) {
        local key = fmt("%s -> %s", c$id$orig_h, c$id$resp_h);
        when (local exists = Broker::exists(store$store, key)) {
                local bool_exists = (exists$result as bool);
                if (!bool_exists) {
                        NOTICE([$note=NewOrigRespPair,
                                $conn=c,
                                $suppress_for=1msec,
                                $msg="New Orig_h Resp_h Pair: " + key]);
                }
                when (local put_result = Broker::put(store$store, key, T, NewConnectionMonitor::history_expiration_interval)) {
                } timeout 5sec { Cluster::log("Timeout when writing connection to store"); }
        } timeout 5sec { Cluster::log("Timeout when trying to see if a connection exists"); }
}

event zeek_init() {
    store = Cluster::create_store("connection_monitoring", NewConnectionMonitor::enable_persistence);
}
