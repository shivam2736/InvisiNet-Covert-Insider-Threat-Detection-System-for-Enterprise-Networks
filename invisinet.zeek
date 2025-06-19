# invisinet.zeek - Covert insider threat detection logic

@load base/protocols/http

module InvisiNet;

export {
    global covert_alerts: table[string] of count = {};
}

event zeek_init() {
    print "InvisiNet loaded.";
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # Example: suspicious keyword detection in HTTP request
    if ( /password/i in unescaped_URI ) {
        covert_alerts[c$id$orig_h] += 1;
        print fmt("Covert Alert: Suspicious HTTP request from %s URI: %s", c$id$orig_h, unescaped_URI);
    }
}

event connection_state_remove(c: connection) {
    if ( covert_alerts[c$id$orig_h] > 0 ) {
        # Log covert alerts to hidden log
        Log::write(InvisiNet::Log, fmt("%s triggered %d covert alerts", c$id$orig_h, covert_alerts[c$id$orig_h]));
    }
}
