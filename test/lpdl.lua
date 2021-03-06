gstate = {init=0, s1=1, s2=2, s3=3, s4=4, s5=5, s6=6, s7=7, s8=8, final=9}
--lde引擎是顺序匹配，顺序由proto_list决定
proto_list={"test", "ppstream", "qqlive", "http", "dns", "ssl", "nat",
			"sametime", "qq_file", "ssh", "ftp", "ftp_data", "qq_test"}
cs_eng_list={"pde", "sde", "lde"} --协议初步识别引擎
as_eng_list={"cdde"}  --协议进一步识别引擎
pkb_dir = {up=1, down=2}
l4_proto = {tcp=6, udp=17}
eng_list={}
proto_list_index = {}
eng_list_index = {}

sde={}
sde.conf = {
                {"0~7", "-8~-1"},--第一个图的范围为0~7以及-8~-1
                --all必须放在最后一个
                {"all"},
           }

--下面的是一个实例协议
--[[demo_proto = {}
    demo_proto.pde="udp/8000,tcp/8000,tcp/14000" -- pde是端口规则，多个规则是并的关系，只要满足一个即可
    demo_proto.sde={                             -- sde是字符规则，由索引和值两部分组成，索引需要用引号括起来，索引范围用~连接，\
                                                    有多种可能性用|分隔开来，值需要用引号括起来，默认是16进制，不需要写0x，如果 \
                                                    是字符串可以用括号括起来，如"0203(windslinux)",可以混用，sde内容也可以是有多种可能性，\
                                                    各种可能性之间用|分割开，分割线的前后是上一段的结束和下一段的开始
                    {["0"]="fe", ["3~5|-5~-1"]="0304|05fe|abcd"}, --索引为0值为fe，并且（一个花括号内的多个索引值为与的关系）\
                                                            索引3~5之间或者-5~-1（最后一个字节）之间有序列为:030405fe
                    {["0"]="fd", ["2~4"]="3456"},           --或者（多个花括号之间是或的关系）索引为0的值为fe，并且索引2~4之间的序列为3456
                }
    demo_proto.lde = function(buf, session)
			  local state = gstate.init
			  if (buf:len() > 2) then
			  if (buf(1,2):uintle() == buf:len() + 2) then
			      state = gstate.final
			  end
			  end
			  return state
			  end
]]

qq_test = {}
qq_test.pde = "udp/8000"
qq_test.sde = {
                {["0"]="02", ["-1"]="03"}
            }
qq_test.lde = function(buf, session)
			  local state = session:state()
			  if (buf:len() >= 5) then
			  if (state == gstate.init) then
				  if (buf:dir() == pkb_dir.up) then
				  	 session:saveindex(4, 2, engine_list_index["lde"] - 1)
                     --save和load的最后一个参数都是slot，一般使用本引擎所在的slot，但如果要记录多个参数，也可以借用其他引擎的slot
				  	 state = gstate.s1
				  end
				  return state
			  end
			  end

			  if (buf:len() >= 5 and state == gstate.s1) then
			     if (buf(4, 2):uintbe() == session:loadnum(engine_list_index["lde"] - 1)) then
				 	state = gstate.final
				 end
			  end
			  return state
			  end


qq_file = {}
qq_file.lde = function(buf, session)
			  local state = session:state()
			  if (buf:len() >= 2) then
			  if (state == gstate.init and buf:getbyte(0) == 0x04 and buf:getbyte(-1) == 0x03) then
				  if (buf:dir() == pkb_dir.up) then
				  	 session:saveindex(1, 2, engine_list_index["lde"] - 1)
                     --save和load的最后一个参数都是slot，一般使用本引擎所在的slot，但如果要记录多个参数，也可以借用其他引擎的slot
				  	 state = gstate.s1
				  end
				  return state
			  end
			  end

			  if (state == gstate.s1 and buf:dir() == pkb_dir.down) then
			     if (buf(1,2):uintbe() == session:loadnum(engine_list_index["lde"] - 1)) then
				 	state = gstate.final
				 end
			  end
			  return state
			  end


ppstream = {}
ppstream.sde = {
                    {["2"]="43"},
                    {["3"]="00"},
                    {["4"]="03"},
                    {["0"]="(PSProtocol)"}
                }
ppstream.lde =
function(buf, session)
    local state = session:state()
	local len = buf:len()
    local proto = buf:proto()
    if (proto == l4_proto.tcp) then
        if (len >= 60 and buf(50, 4):uintbe() == 0x0 and buf(0, 10):string() == "PSProtocol") then
            state = gstate.final
        end
        return state
    end

    if (proto == l4_proto.udp) then
        if (len < 2) then
            return state
        end
	    local buf_hd = buf(0,2):uintle()
        if (len >2 and buf:getbyte(2) == 0x43 and (((len - 4) == buf_hd)
            or (len == buf_hd) or (len >= 6 and (len - 6) == buf_hd))) then
            state = state + 1
            if (state == 5) then
                state = gstate.final
            end
            return state
        end
        if (state == 0 and len > 4 and (((len - 4) == buf_hd)
            or (len ==buf_hd) or (len >= 6 and (len - 6) == buf_hd))) then
            state = gstate.s7
            return state
        end
        if (state == gstate.s7 and len > 4 and buf:getbyte(3) == 0x0 and (((len - 4) == buf_hd)
            or (len == buf_hd) or (len >= 6 and (len - 6) == buf_hd)) and buf:getbyte(2) == 0x0 and
            buf:getbyte(4) == 0x3) then
            state = gstate.final
        end
    end
    return state
end

qqlive = {}
qqlive.sde = {
                {["0"]="fe"}
             }
qqlive.lde = function(buf, session)
			  	 local state = gstate.init
				 -- ppsteam head length is 4
				     if (buf:len() >= 5) then
					 local val1 = buf(1,2):uintle()
					 local val2 = buf(3,2):uintbe()
				     if (val1 == buf:len()-3 and val1 == val2) then
				         state = gstate.final
			      	 end
				 end
				 return state
				 end

nat = {}
nat.lde = function(buf, sesison)
		      local state
		      if (buf:len() >= 4) then
		      if (buf(0,4):uintbe() == 0x00010008) then
		          state = gstate.final
		      end
	          end
		  return state
		  end

http = {}
http.pde = "tcp/80"

dns = {}
dns.pde = "udp/53"

ssl = {}
ssl.pde = "tcp/443"

sametime = {}
sametime.pde = "tcp/1533"

ssh = {}
ssh.pde = "tcp/22"


ftp = {}
ftp.pde = "tcp/21"
ftp.cdde = function(buf, session, meta)
           if (buf:len() >= 4) then
                if (buf(0, 4):string() == "PORT") then
                    local j = 5
                    local ip, port
                    ip, j = get_ftp_active_code(buf, j, 4)
                    port, j = get_ftp_active_code(buf, j, 2)
                    meta:add_ff(ip, port, proto_list_index["ftp_data"] - 1) --lua的index从1开始
               elseif (buf(0, 3):string() == "226") then
                    return gstate.final
                end
           end
           return gstate.s2
           end

ftp_data = {}
ftp_data.pde = "tcp/20"

function get_ftp_active_code(buf, j, bytes)
    local prev, i
    local value, v, b
    value = 0
    for i=1, bytes do
        len = 0
        prev = j
        b = buf:getbyte(j)
        v = 0
        while (b ~= 0x2c and b ~= 0x0d) do
            j = j + 1
            v = v * 10 + b - 0x30;
            b = buf:getbyte(j)
        end
        for k=1, bytes-i do
            v = v * 256
        end
        value = value + v
        j = j + 1
    end
    return value, j
end

function reverse_table(obj)
    local k, v
    local revobj={}
    for k,v in pairs(obj) do
        revobj[v] = k
    end
    return revobj
end

function merge_table(obj1, obj2)
    local obj={}
    local k, v
    for k, v in pairs(obj1) do
        table.insert(obj, v)
    end
    for k, v in pairs(obj2) do
        table.insert(obj, v)
    end
    return obj
end

function show_table(obj)
    for k, v in pairs(obj) do
        print("key="..k..", v=".. v)
    end
end


function init()
    local k, v
    proto_list_index = reverse_table(proto_list)
    engine_list = merge_table(cs_eng_list, as_eng_list)
    engine_list_index = reverse_table(engine_list)
end

init()

