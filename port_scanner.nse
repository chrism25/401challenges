-- File for Nmap NSE --
-- HEAD --
description = [[
Determines if a  port is open, if none is given, it will scan all
]]

-- RULE --
portrule = function(host, port)
        return port.protocol == "tcp"
                and port.state == "open"
end

-- ACTION --
action = function(host, port)
        return "The port is open"
end
