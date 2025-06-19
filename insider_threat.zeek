Custom Zeek Script for Insider Threat Detection
Note: This is a Zeek script written in Python-like syntax for clarity
"""

ZEEK_SCRIPT = """
# insider_threat.zeek - Advanced Insider Threat Detection

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/ftp
@load base/protocols/smb
@load base/protocols/ssh

module InsiderThreat;

export {
    type ThreatIndicator: record {
        user: string &optional;
        src_ip: addr;
        dst_ip: addr;
        action: string;
        severity: count;
        details: string &optional;
        timestamp: time;
    };
    
    type UserProfile: record {
        username: string;
        normal_hours: set[count];
        typical_hosts: set[addr];
        data_volume_baseline: double;
        last_seen: time;
    };
    
    redef enum Log::ID += { THREAT_LOG, PROFILE_LOG };
    
    const sensitive_keywords = {
        "confidential", "secret", "proprietary", "merger", 
        "acquisition", "layoffs", "password", "credential"
    } &redef;
    
    const sensitive_extensions = {
        ".doc", ".docx", ".pdf", ".xls", ".xlsx", 
        ".ppt", ".pptx", ".sql", ".db"
    } &redef;
    
    global user_profiles: table[string] of UserProfile;
    global data_transfers: table[addr] of double;
}

# Initialize logging
event zeek_init() {
    Log::create_stream(InsiderThreat::THREAT_LOG, 
        [$columns=ThreatIndicator, $path="insider_threats"]);
    Log::create_stream(InsiderThreat::PROFILE_LOG, 
        [$columns=UserProfile, $path="user_profiles"]);
}

# Monitor HTTP requests for sensitive data access
event http_request(c: connection, method: string, original_URI: string, 
                  unescaped_URI: string, version: string) {
    
    local current_hour = to_count(strftime("%H", network_time()));
    local user = extract_user_from_http(c);
    
    # Check for after-hours access
    if (current_hour < 7 || current_hour > 19) {
        local threat: ThreatIndicator = [
            $user = user,
            $src_ip = c$id$orig_h,
            $dst_ip = c$id$resp_h,
            $action = "after_hours_web_access",
            $severity = 5,
            $details = fmt("URI: %s at %s", unescaped_URI, strftime("%H:%M", network_time())),
            $timestamp = network_time()
        ];
        Log::write(InsiderThreat::THREAT_LOG, threat);
    }
    
    # Check for sensitive file access
    for (ext in sensitive_extensions) {
        if (ext in unescaped_URI) {
            local threat: ThreatIndicator = [
                $user = user,
                $src_ip = c$id$orig_h,
                $dst_ip = c$id$resp_h,
                $action = "sensitive_file_access",
                $severity = 7,
                $details = fmt("Accessed: %s", unescaped_URI),
                $timestamp = network_time()
            ];
            Log::write(InsiderThreat::THREAT_LOG, threat);
            break;
        }
    }
}

# Monitor file transfers for data exfiltration
event file_over_new_connection(f: fa_file, c: connection) {
    if (!c$id$orig_h in Site::local_nets) {
        # External file transfer detected
        local user = extract_user_from_conn(c);
        local file_size = f$info$total_bytes;
        
        if (file_size > 50*1024*1024) {  # 50MB threshold
            local threat: ThreatIndicator = [
                $user = user,
                $src_ip = c$id$orig_h,
                $dst_ip = c$id$resp_h,
                $action = "large_file_exfiltration",
                $severity = 9,
                $details = fmt("File size: %d bytes", file_size),
                $timestamp = network_time()
            ];
            Log::write(InsiderThreat::THREAT_LOG, threat);
        }
    }
}

# Monitor SMB access patterns
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, req: SMB2::TreeConnectRequest) {
    local user = extract_user_from_smb(c, hdr);
    local share_path = req$path;
    
    # Check for admin share access
    if (/ADMIN\$|C\$|IPC\$/ in share_path) {
        local threat: ThreatIndicator = [
            $user = user,
            $src_ip = c$id$orig_h,
            $dst_ip = c$id$resp_h,
            $action = "admin_share_access",
            $severity = 8,
            $details = fmt("Share: %s", share_path),
            $timestamp = network_time()
        ];
        Log::write(InsiderThreat::THREAT_LOG, threat);
    }
}

# Monitor SSH sessions for privilege escalation
event ssh_auth_successful(c: connection, auth_method: string, auth_user: string) {
    if (auth_user == "root" || auth_user == "administrator") {
        local threat: ThreatIndicator = [
            $user = auth_user,
            $src_ip = c$id$orig_h,
            $dst_ip = c$id$resp_h,
            $action = "privileged_ssh_login",
            $severity = 7,
            $details = fmt("Method: %s", auth_method),
            $timestamp = network_time()
        ];
        Log::write(InsiderThreat::THREAT_LOG, threat);
    }
}

# Email monitoring for data leakage
event smtp_data(c: connection, is_orig: bool, data: string) {
    if (is_orig) {
        for (keyword in sensitive_keywords) {
            if (keyword in to_lower(data)) {
                local user = extract_user_from_smtp(c);
                local threat: ThreatIndicator = [
                    $user = user,
                    $src_ip = c$id$orig_h,
                    $dst_ip = c$id$resp_h,
                    $action = "sensitive_email_content",
                    $severity = 6,
                    $details = fmt("Keyword detected: %s", keyword),
                    $timestamp = network_time()
                ];
                Log::write(InsiderThreat::THREAT_LOG, threat);
                break;
            }
        }
    }
}

# User profiling functions
function extract_user_from_http(c: connection): string {
    # Extract username from HTTP headers or authentication
    return "unknown_user";  # Simplified for example
}

function extract_user_from_conn(c: connection): string {
    # Extract username from connection context
    return "unknown_user";  # Simplified for example
}

function extract_user_from_smb(c: connection, hdr: SMB2::Header): string {
    # Extract username from SMB headers
    return "unknown_user";  # Simplified for example
}

function extract_user_from_smtp(c: connection): string {
    # Extract username from SMTP session
    return "unknown_user";  # Simplified for example
}
