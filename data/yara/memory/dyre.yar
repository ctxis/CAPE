// Copyright (C) 2010-2014 Cuckoo Foundation.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

// The contents of this file are Yara rules processed by procmemory.py processing
// module. Add your signatures here.
rule DyreCfgServerList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dyre server list"

    strings:
        $buf = /\<serverlist\>.*\<\/serverlist\>/s

    condition:
        $buf
}

rule DyreCfgInjectsList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dyre web injects"

    strings:
        $buf = /\<litem\>.*\<\/litem\>/s

    condition:
        $buf
}

rule DyreCfgRedirectList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dyre redirects list"

    strings:
        $buf = /\<rpcgroup\>.*\<\/rpcgroup\>/s

    condition:
        $buf
}
