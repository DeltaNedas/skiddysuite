#!/usr/bin/env lua5.3

local Args = {...}

local Help = {
	"Usage: porthack.lua [-h/-f (file)/-p (port)/-w]",
	"Example: ./porthack.lua -f ips.txt -p 45",
	"See man page (TODO) for more info."
}

local continue = 0

local function printf(text, ...)
	return io.write(text:format(...))
end

local function IsIPv4(IP)
	if IP:match("^[^%d%.]") then
		return false
	end
	local Octets = {IP:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")}
	if #Octets ~= 4 then
		return false
	end
	for _, Octet in pairs(Octets) do
		if tonumber(Octet) < 0 or tonumber(Octet) > 255 then
			return false
		end
	end
	return true
end

function string.split(String, Seperator)
	local Table = {}
	Seperator = Seperator or " "
	String = tostring(String)
	for Text in String:gmatch("[^%"..Seperator.."]+") do
		table.insert(Table, Text)
	end
	return Table
end

local Wait = true

local function WaitEnter()
	if Wait then
		io.write("Please press enter to continue.")
		io.read("*l")
	end
end

local IPs = {}
local Port = ""

for i, Arg in pairs(Args) do
	if Arg == "-h" or Arg == "--help" then
		for _, Line in pairs(Help) do
			print(Line)
		end
		os.exit(0)
	elseif Arg == "-f" or Arg == "--file" then
		continue = 1
		local FileName = Args[i + 1]
		if not FileName then
			printf("Please provide a file name after %s.\n", Arg)
			os.exit(1)
		end
		local File, Err = io.open(FileName, "r")
		if not File then
			printf("Error occurred while reading %s.\n", Err)
			os.exit(1)
		end
		IPs = File:read("*all"):split("\n")
		printf("Read target IPs from %s.\n", FileName)
	elseif Arg == "-p" or Arg == "--port" then
		continue = 1
		local portString = Args[i + 1]
		if not portString then
			printf("Please provide a port after %s.\n", Arg)
			os.exit(1)
		end
		local port = tonumber(portString)
		if port < 0 or port > 65535 then
			print("Please provide a valid port (between 0 and 65535).")
			os.exit(1)
		end
		printf("Using port %d.\n", port)
		Port = "-p"..tostring(port).." "
	elseif Arg == "-w" or Arg == "--wait" then
		Wait = true
		print("Requiring you to press enter to start next nmap scan.")
	elseif continue > 0 then
		continue = continue - 1
	else
		printf("Unknown option: %s.\n", Arg)
		os.exit(1)
	end
end

if #IPs > 0 then
	print("Running nmap on IPs.")

	for _, IP in pairs(IPs) do
		if IsIPv4(IP) then
			os.execute("nmap -sS -O -Pn "..Port..IP)
			WaitEnter()
		else
			printf("IP '%s' is not a valid IPv4 address, skipping.\n", IP)
		end
	end
else
	print("Running nmap on IPs from stdin, type an IP to start.")
	print("Type \"exit\" to exit.")
	local Running = true
	while Running do
		io.write("> ")
		local Input = io.read("*l")
		local Previous = ""
		if Input ~= "" then
			if Input == "exit" or Input == "e" or Input == "quit" or Input == "q" then
				Running = false
			elseif IsIPv4(Input) then
				Previous = Input
				os.execute("nmap -sS -O -Pn "..Port..Input)
				WaitEnter()
			elseif Input == "!!" or Input == "previous" or Input == "prev" or Input == "p" then
				if Previous then
					os.execute("nmap -sS -O -Pn "..Port..Previous)
				end
				WaitEnter()
			else
				printf("Invalid input: %s.\n", Input)
			end
		end
	end
end
