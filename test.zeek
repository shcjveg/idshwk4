global codeTable: table[addr] of table[string] of table[string] of count = table();
global alertcode: count = 404;
global ts:time = 0;

# 使用字典记录每个addr对应的uri的404数量和总数
# 注意时间控制 10min
# codeTable[addr][uri][404code or all] = count

event http_reply(c: connection, version: string, code: count, reason: string)
{
	if(time_to_double(c$start_time)-time_to_double(ts)>600)
	{
		ts = c$start_time;
		for(address in codeTable){
			local alertcount:double = 0;
			local allcount:double = 0;
			local uricount:double = 0;
			for (uri in codeTable[address]){
				if("alertcode" in codeTable[address][uri]){
					alertcount += codeTable[address][uri]["alertcode"];
					uricount += 1;
				}
				allcount += codeTable[address][uri]["allcode"];
			}
			if(alertcount>2 && (alertcount/allcount) > 0.2 && uricount/alertcount > 0.5){
				print fmt("%s is a scanner with %.0f scan attempts on %.0f urls",address,alertcount,uricount);
				print alertcount,uricount;
			}
		}
		codeTable = table();
	}
	# 如果是404，则codeTable[alertcode] +1，无论如何codeTable[allcode] +1
	if (c$id$orig_h in codeTable){
		if(c$http$uri in codeTable[c$id$orig_h]){
			if("allcode" in codeTable[c$id$orig_h][c$http$uri]){
				++codeTable[c$id$orig_h][c$http$uri]["allcode"];
				if("code" in codeTable[c$id$orig_h][c$http$uri]){
					if(code == alertcode){
						++codeTable[c$id$orig_h][c$http$uri]["alertcode"];
					}
				}else{
					if(code == alertcode){
						codeTable[c$id$orig_h][c$http$uri]["alertcode"] = 1;
					}
				}
			}else{
				codeTable[c$id$orig_h][c$http$uri]["allcode"] = 1;
				if(code == alertcode){
					codeTable[c$id$orig_h][c$http$uri]["alertcode"] = 1;
				}
			}
			
		}else{
			codeTable[c$id$orig_h][c$http$uri] = table();
			codeTable[c$id$orig_h][c$http$uri]["allcode"] = 1;
			if(code == alertcode){
				codeTable[c$id$orig_h][c$http$uri]["alertcode"] = 1;
			}
		}
	}else {
		codeTable[c$id$orig_h] = table();
		codeTable[c$id$orig_h][c$http$uri] = table();
		codeTable[c$id$orig_h][c$http$uri]["allcode"] = 1;
		if(code == alertcode){
			codeTable[c$id$orig_h][c$http$uri]["alertcode"] = 1;
		}
	}
}

event zeek_done(){
	for(address in codeTable){
		local alertcount:double = 0;
		local allcount:double = 0;
		local uricount:double = 0;
		for (uri in codeTable[address]){
			if("alertcode" in codeTable[address][uri]){
				alertcount += codeTable[address][uri]["alertcode"];
				uricount += 1;
			}
			allcount += codeTable[address][uri]["allcode"];
		}
		if(alertcount>2 && (alertcount/allcount) > 0.2 && uricount/alertcount > 0.5){
			print fmt("%s is a scanner with %.0f scan attempts on %.0f urls",address,alertcount,uricount);
		}
	}
}


