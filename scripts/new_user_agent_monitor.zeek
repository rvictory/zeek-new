# This script will monitor for new HTTP User-Agents
# It uses an SQLite backed database to persist across Zeek restarts. This also means that it won't really scale well
# Alerts end up in the `notice.log` log
module NewUserAgentMonitor;

export {
    redef enum Notice::Type += {
        NewUserAgent
    };

    option history_expiration_interval = 30days;
    option enable_persistence = T;
}

global store: Cluster::StoreInfo;

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
        if (!c?$http || !c$http?$user_agent) {
            return;
        }
        local key = c$http$user_agent;
        when (local exists = Broker::exists(store$store, key)) {
                local bool_exists = (exists$result as bool);
                if (!bool_exists) {
                    local host = "";
                    if (c$http?$host) {
                        host = c$http$host;
                    }
                        NOTICE([$note=NewUserAgent,
                                $conn=c,
                                $suppress_for=1msec,
                                $msg="New User-Agent: " + key + " connecting to host " + host]);
                }
                when (local put_result = Broker::put(store$store, key, T, NewUserAgentMonitor::history_expiration_interval)) {
                } timeout 5sec { Cluster::log("Timeout when writing user-agent to store"); }
        } timeout 5sec { Cluster::log("Timeout when trying to see if a user-agent exists"); }
}

event zeek_init() {
    store = Cluster::create_store("new_user_agent_monitoring", NewUserAgentMonitor::enable_persistence);
}
