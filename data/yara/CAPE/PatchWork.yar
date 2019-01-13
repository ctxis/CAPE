rule PatchWork
{
    meta:
    description = "PatchWork"
        author = " avman1995"
        reference = "https://app.any.run/tasks/7ef05c98-a4d4-47ff-86e5-8386f8787224"
        date = "2019/01"
        maltype = "APT"
        cape_type = "PatchWork Payload"
 
 strings:
    $string1 = "AppId" wide
    $string2 = "AXE: #" wide
    $string3 = "Bld: %s.%s.%s" wide
    $string4 = "%s@%s %s" wide
    $string5 = "c:\intel\" wide
   
   condition:
    all of ($string*)
}