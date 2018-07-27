#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

-----------------����淶˵��-----------------
--[[
���г��������ܶ������Ƶ�
˵��1>�Դ���Ӧ��Ĵ���
	��processmsg�����л���ø��������֧�������֧�����ɹ������ڲ�����httpӦ��
	�������ʧ�ܣ���processmsg�жϷ���ֵͳһӦ��
˵��2>�Լ�Ȩ�ȳ��湲�ԵĶ������ÿ���ͳһ���ű���ȥִ��
˵��3>HTTPӦ��ͷͳһ����OK���������ڲ�����Ӧ�ô��󣬻���ϵͳ����
]]


--[�趨����·��]
--���Զ����·������package������·���С�Ҳ���Լӵ���������LUA_PATH��
--�ŵ�init_lus_path.lua�У���Ȼ�Ļ���ÿһ���������ʱ�򶼻��ȫ�ֱ���
--package.path�������ã�����

--[����������ģ��]
local cjson = require("cjson.safe")

--[������������]
local access_key = nil
local secret_key = nil
local store_type = nil 
local bucket_name = nil
local bucket_domain = nil
local bucket_domain_internal = nil

--[[
make_signature: ����header�����ǩ��ͷ
headers: ����ͷ�����ʲô���ݣ�һ����Date
objname: Ҫǩ���Ķ�������
--]]
function make_signature(method,headers,objname)
	local param = {}
	table.insert(param, string.upper(method))
	table.insert(param, headers['Content-MD5'] or '')
	table.insert(param, headers['Content-Type'] or '')
	table.insert(param, headers['Date'])

	local canonicalizedResource = '/'..bucket_name..'/'
	if objname then
		canonicalizedResource = canonicalizedResource .. objname
	end
	
	table.insert(param,canonicalizedResource)
	local string2Sign = table.concat(param,'\n')
	local signature = ngx.encode_base64(ngx.hmac_sha1(secret_key,string2Sign))
	local auth = store_type.." "..access_key..":"..signature
	return auth,signature
end

--[[
ǩ����
--]]
function do_sign(jreq)
	if not jreq["DDIP"]["Body"]["SerialNumber"] 
        or not jreq["DDIP"]["Body"]["ObjName"]
    then
		ngx.log(ngx.ERR, "do_sign_upload invalid args")
		return false,"do_sign_upload invalid args"
	end
	
	local serinum = jreq["DDIP"]["Body"]["SerialNumber"]
	local objname = jreq["DDIP"]["Body"]["ObjName"]

	local ostime = os.date("!%a, %d %b %Y %H:%M:%S GMT")
    local put_header = {}     
	put_header["Date"] = ostime
    
    local utctime = ngx.time() + 3600
	local get_header = {}
	get_header["Date"] = utctime

    --ǩ��
	local put_auth,put_signature = make_signature("PUT",put_header,objname)
	if not put_auth or not put_signature then 
		return false,"make_signature PUT failed"
	end
    put_signature = ngx.escape_uri(put_signature)
    
    local _,get_signature = make_signature("GET",get_header,objname)
	if not get_signature then 
		return false,"make_signature GET failed"
	end
    get_signature = ngx.escape_uri(get_signature)
    local url =  "/"..objname
    local put_url = url.."?"..store_type.."AccessKeyId="..access_key.."&Signature="..put_signature
    local get_url = url.."?"..store_type.."AccessKeyId="..access_key.."&Expires="..utctime.."&Signature="..get_signature

	--��֯Ӧ���
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_SIGN_RSP"
	jrsp["DDIP"]["Header"]["ErrorNum"] = "200"
	jrsp["DDIP"]["Header"]["ErrorString"] = "Sucess OK"
	jrsp["DDIP"]["Body"] = {}
	jrsp["DDIP"]["Body"]["Host"] = bucket_domain
    jrsp["DDIP"]["Body"]["HostInternal"] = bucket_domain_internal
    jrsp["DDIP"]["Body"]["Url"] = url 
    jrsp["DDIP"]["Body"]["Date"] = put_header["Date"]
    jrsp["DDIP"]["Body"]["Authorization"] = put_auth
	jrsp["DDIP"]["Body"]["PutUrl"] = put_url
	jrsp["DDIP"]["Body"]["GetUrl"] = get_url
    
	local resp_str = cjson.encode(jrsp) 
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
	return true
end

--����Ӧ�����ݱ�
function send_resp_table (status,resp)
	if not resp or type(resp) ~= "table" then
		ngx.log(ngx.ERR, "send_resp_table:type(resp) ~= table", type(resp))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTPӦ��ͷͳһ����OK���������ڲ�����Ӧ�ô��󣬻���ϵͳ����
	--ngx.status = status
	local resp_str = cjson.encode(resp)
	--ngx.log(ngx.NOTICE, "send_resp_table:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end
function send_resp_string(status,message_type,error_string)
	if not message_type or type(message_type) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(message_type) ~= string", type(message_type))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	if not error_string or type(error_string) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(error_string) ~= string", type(error_string))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTPӦ��ͷͳһ����OK���������ڲ�����Ӧ�ô��󣬻���ϵͳ����
	--ngx.status = status
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = message_type
	jrsp["DDIP"]["Header"]["ErrorNum"] = string.format("%d",status)
	jrsp["DDIP"]["Header"]["ErrorString"] = error_string
	local resp_str = cjson.encode(jrsp)
	--ngx.log(ngx.NOTICE, "send_resp_string:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end

--������Ĳ�������Ч�Լ�飬���ؽ�������Ϣ�����json����
function get_request_param()
	--ngx.log(ngx.NOTICE, "get_request_param:",ngx.var.request_body)
    local req_body, err = cjson.decode(ngx.var.request_body)
	if not req_body then
		ngx.log(ngx.ERR, "get_request_param:req body is not a json")
		return nil, "req body is not a json"
    end
    if not req_body["DDIP"]
        or not req_body["DDIP"]["Header"]
        or not req_body["DDIP"]["Header"]["Version"]
        or not req_body["DDIP"]["Header"]["CSeq"]
        or not req_body["DDIP"]["Header"]["MessageType"]
        or not req_body["DDIP"]["Body"]
        or type(req_body["DDIP"]["Header"]["Version"]) ~= "string"
        or type(req_body["DDIP"]["Header"]["CSeq"]) ~= "string"
        or type(req_body["DDIP"]["Header"]["MessageType"]) ~= "string"
		then
        ngx.log(ngx.ERR, "invalid args")
        return nil, "invalid protocol format args"
    end
    return req_body, "success"
end

--��Ϣ���������
function process_msg()
	--��ȡ�������
	local jreq, err = get_request_param()
	if not jreq then
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any",err);
	    return
	end

	--�������
	if(jreq["DDIP"]["Header"]["MessageType"] == "MSG_SIGN_REQ") then
		local ok, err = do_sign(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_SIGN_RSP",err);
		end
	else
		ngx.log(ngx.ERR, "invalid MessageType",jreq["DDIP"]["Header"]["MessageType"])
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any","Invalid MessageType");
	end
	return
end

--����������Ϣ(��������������)
local function load_ip_addr()
	access_key = ngx.shared.shared_data:get("AccessKey")
	if access_key == nil  then
		ngx.log(ngx.ERR,"get AccessKey failed ")
        return false
	end
    secret_key = ngx.shared.shared_data:get("SecretKey")
	if secret_key == nil  then
		ngx.log(ngx.ERR,"get SecretKey failed ")
        return false
	end
    store_type = ngx.shared.shared_data:get("StoreType")
	if store_type == nil  then
		ngx.log(ngx.ERR,"get StoreType failed ")
        return false
	end
    if store_type == "S3" or store_type == "OBS" then
		store_type = "AWS"
	end
    
    bucket_name = ngx.shared.shared_data:get("BucketName")
	if bucket_name == nil  then
		ngx.log(ngx.ERR,"get BucketName failed ")
        return false
	end
    bucket_domain = ngx.shared.shared_data:get("BucketDomain")
	if bucket_domain == nil  then
		ngx.log(ngx.ERR,"get BucketDomain failed ")
        return false
	end
    bucket_domain_internal = ngx.shared.shared_data:get("BucketDomainInternal")
	if bucket_domain_internal == nil  then
		ngx.log(ngx.ERR,"get BucketDomainInternal failed ")
        return false
	end
	return true
end

--�������
--print("get request_body:"..ngx.var.request_body)
--print("=====================new request=======================\n")
--print("get server_port::::",ngx.var.server_port,type(ngx.var.server_port))

--����ͨ���˿ں���������https��http
--ngx.var.server_port

local ok = load_ip_addr()
if not ok then
    ngx.log(ngx.ERR,"load_ip_addr failed ")
    return false
end
process_msg()

