import httpclient, asyncdispatch, json, options
import ../objects, ../constants
import tables, regex, os, sequtils, strutils
import uri, mimetypes
when defined(windowsNativeTls) and defined(windows):
    import winlean, unicode, threadpool, random

var
    fatalErr = true
    ratelimited, global = false
    global_retry_after = 0.0
    invalid_requests = 0

type
    BasicResponse = object
        status: HttpCode
        headers: Table[string, seq[string]]
        body: string

proc lowerKey(key: string): string = key.toLowerAscii

proc addHeader(tbl: var Table[string, seq[string]], key, val: string) =
    let k = key.lowerKey
    if k in tbl:
        tbl[k].add(val)
    else:
        tbl[k] = @[val]

proc getHeader(tbl: Table[string, seq[string]], key: string, defaultVal = ""): string =
    let k = key.lowerKey
    if k in tbl and tbl[k].len > 0:
        result = tbl[k][0]
    else:
        result = defaultVal

proc toHeaderTable(headers: HttpHeaders): Table[string, seq[string]] =
    for k, vals in headers:
        result[k.lowerKey] = @[vals]

proc toBasicResponse(resp: AsyncResponse): Future[BasicResponse] {.async.} =
    var tbl = resp.headers.toHeaderTable
    var bodyStr = ""

    if resp.headers.hasKey("content-type"):
        let ct = resp.headers["content-type"].toString
        if ct.contains("application/json"):
            let body = resp.body
            if not (await withTimeout(body, 60_000)):
                raise newException(RestError, "Body took too long to parse.")
            bodyStr = await body
        else:
            let body = resp.body
            if not (await withTimeout(body, 60_000)):
                raise newException(RestError, "Body took too long to parse.")
            bodyStr = await body
    else:
        let body = resp.body
        if not (await withTimeout(body, 60_000)):
            raise newException(RestError, "Body took too long to parse.")
        bodyStr = await body

    result = BasicResponse(status: resp.code, headers: tbl, body: bodyStr)

when defined(windowsNativeTls) and defined(windows):
    type
        HINTERNET* = pointer

    const
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
        WINHTTP_NO_PROXY_NAME: pointer = nil
        WINHTTP_NO_PROXY_BYPASS: pointer = nil
        WINHTTP_FLAG_SECURE = 0x00800000
        WINHTTP_QUERY_STATUS_CODE = 19
        WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
        WINHTTP_QUERY_RAW_HEADERS_CRLF = 22
        WINHTTP_NO_HEADER_INDEX = 0
        WINHTTP_ADDREQ_FLAG_ADD = 0x20000000
        WINHTTP_ADDREQ_FLAG_REPLACE = 0x80000000

    proc WinHttpOpen(userAgent: WideCString, accessType: int32, proxyName: pointer,
            proxyBypass: pointer, flags: uint32): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpOpen".}
    proc WinHttpCloseHandle(handle: HINTERNET): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpCloseHandle".}
    proc WinHttpConnect(session: HINTERNET, serverName: WideCString, serverPort: uint16,
            reserved: uint32): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpConnect".}
    proc WinHttpOpenRequest(connect: HINTERNET, verb: WideCString, objectName: WideCString,
            version: WideCString, referrer: WideCString, acceptTypes: pointer, flags: uint32): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpOpenRequest".}
    proc WinHttpAddRequestHeaders(request: HINTERNET, headers: WideCString, headersLength: int32,
            modifiers: uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpAddRequestHeaders".}
    proc WinHttpSendRequest(request: HINTERNET, headers: WideCString, headersLength: int32,
            optional: pointer, optionalLength: int32, totalLength: int32, context: uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpSendRequest".}
    proc WinHttpReceiveResponse(request: HINTERNET, reserved: pointer): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpReceiveResponse".}
    proc WinHttpQueryHeaders(request: HINTERNET, infoLevel: uint32, name: pointer,
            buffer: pointer, bufferLength: ptr uint32, index: ptr uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpQueryHeaders".}
    proc WinHttpReadData(request: HINTERNET, buffer: pointer, bufferSize: uint32,
            bytesRead: ptr uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpReadData".}
    proc WinHttpSetTimeouts(request: HINTERNET, resolveTimeout, connectTimeout,
            sendTimeout, receiveTimeout: int32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpSetTimeouts".}

    proc closeHandleSafely(h: var HINTERNET) =
        if h != nil:
            discard WinHttpCloseHandle(h)
            h = nil

    proc parseRawHeaders(raw: string): Table[string, seq[string]] =
        for line in raw.splitLines():
            if line.len == 0 or line.startsWith("HTTP/"): continue
            let parts = line.split(":", 1)
            if parts.len == 2:
                addHeader(result, parts[0].strip(), parts[1].strip())

    proc winHttpRequest(meth, url, body: string; headers: Table[string, seq[string]];
            timeoutMs = 20_000): BasicResponse {.gcsafe.} =
        let u = parseUri(url)
        let host = u.hostname
        var path = if u.path.len == 0: "/" else: u.path
        if u.query.len > 0:
            path &= "?" & u.query

        let secure = u.scheme.lowerKey == "https"
        let port = if u.port.len > 0: uint16(parseInt(u.port)) else: (if secure: 443 else: 80)

        var hSession = WinHttpOpen(newWideCString(libAgent), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
        if hSession.isNil:
            raise newException(RestError, "WinHttpOpen failed: " & $getLastError())
        defer: closeHandleSafely(hSession)

        var hConnect = WinHttpConnect(hSession, newWideCString(host), port, 0)
        if hConnect.isNil:
            raise newException(RestError, "WinHttpConnect failed: " & $getLastError())
        defer: closeHandleSafely(hConnect)

        var hRequest = WinHttpOpenRequest(hConnect, newWideCString(meth), newWideCString(path),
            nil, nil, nil, if secure: WINHTTP_FLAG_SECURE else: 0)
        if hRequest.isNil:
            raise newException(RestError, "WinHttpOpenRequest failed: " & $getLastError())
        defer: closeHandleSafely(hRequest)

        let t = int32(timeoutMs)
        discard WinHttpSetTimeouts(hRequest, t, t, t, t)

        var headerBlob = ""
        for k, vals in headers:
            for v in vals:
                headerBlob.add(k & ": " & v & "\r\n")
        if headerBlob.len > 0:
            let hdrLen = int32(-1)
            let hdrMode = uint32(WINHTTP_ADDREQ_FLAG_ADD or WINHTTP_ADDREQ_FLAG_REPLACE)
            discard WinHttpAddRequestHeaders(hRequest, newWideCString(headerBlob), hdrLen, hdrMode)

        var optPtr: pointer = nil
        var optLen = 0'i32
        if body.len > 0:
            optPtr = unsafeAddr body[0]
            optLen = int32(body.len)

        if not WinHttpSendRequest(hRequest, nil, 0, optPtr, optLen, optLen, 0):
            raise newException(RestError, "WinHttpSendRequest failed: " & $getLastError())

        if not WinHttpReceiveResponse(hRequest, nil):
            raise newException(RestError, "WinHttpReceiveResponse failed: " & $getLastError())

        var statusCode: uint32 = 0
        var statusSize: uint32 = uint32(sizeof(uint32))
        if not WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
                nil, addr statusCode, addr statusSize, nil):
            raise newException(RestError, "WinHttpQueryHeaders(status) failed: " & $getLastError())

        var hdrSize: uint32 = 0
        discard WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, nil, nil, addr hdrSize, nil)
        var hdrBuf = cast[WideCString](alloc(hdrSize + 2))
        defer: dealloc(hdrBuf)

        if not WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, nil, hdrBuf, addr hdrSize, nil):
            raise newException(RestError, "WinHttpQueryHeaders(raw) failed: " & $getLastError())

        let rawHeaders = $hdrBuf
        var parsedHeaders = parseRawHeaders(rawHeaders)

        var bodyAcc = newStringOfCap(4096)
        var buf = newString(8192)
        while true:
            var read: uint32 = 0
            if not WinHttpReadData(hRequest, addr buf[0], uint32(buf.len), addr read):
                raise newException(RestError, "WinHttpReadData failed: " & $getLastError())
            if read == 0: break
            bodyAcc.add(buf[0 ..< int(read)])

        result = BasicResponse(status: HttpCode(statusCode.int), headers: parsedHeaders, body: bodyAcc)
        
proc `<=`(x, y: HttpCode): bool =
    result = x.int <= y.int

proc parseRoute(endpoint, meth: string): string =
    let
        majorParams = @["channels", "guilds", "webhooks"]
        params = endpoint.findAndCaptureAll(re"([a-z-]+)")

    var route = endpoint.split("?", 2)[0]

    for param in params:
        if param in majorParams:
            if param == "webhooks":
                route = route.replace(
                    re"webhooks\/[0-9]{17,19}\/.*",
                    "webhooks/:id/:token"
                )

            route = route.replace(re"\/(?:[0-9]{17,19})", "/:id")
        elif param == "reactions":
            route = route.replace(re"reactions\/[^/]+", "reactions/:id")

    if route.endsWith("messages/:id") and meth == "DELETE":
        return meth & route

    result = route

proc handleRoute(api: RestApi, glbal = false; route = "") {.async.} =
    var rl: tuple[retry_after: float, ratelimited: bool]

    if glbal:
        rl = (global_retry_after, ratelimited)
    elif route != "":
        rl = (api.endpoints[route].retry_after,
            api.endpoints[route].ratelimited)

    if rl.ratelimited:
        log "Delaying " & (if global: "all" else: "HTTP") &
            " requests in (" & $(int(rl.retry_after * 1000)) &
            "ms) [" & (if glbal: "global" else: route) & "]"

        await sleepAsync int(rl.retry_after * 1000)

        if not glbal:
            api.endpoints[route].ratelimited = false
        else:
            ratelimited = false
            global = false

proc discordDetailedErrors(errors: JsonNode, extra = ""): seq[string] =
    let ext = extra

    case errors.kind:
    of JArray:
        var err: seq[string] = @[]

        for e in errors.elems:
            err.add("\n    - " & ext & ": " & e["message"].str)
        result = result.concat(err)
    of JObject:
        for err in errors.pairs:
            return discordDetailedErrors(err.val, (if ext == "":
                    err.key & "." & err.key else: ext & "." & err.key))
    else:
        discard

proc discordErrors(data: JsonNode): string =
    result = data["message"].str & " (" & $data["code"].getInt & ")"

    if "errors" in data:
        result &= discordDetailedErrors(data["errors"]).join("\n")

proc request*(api: RestApi, meth, endpoint: string;
            pl, audit_reason = ""; mp: MultipartData = nil;
            auth = true): Future[JsonNode] {.async.} =
    ## Makes HTTP requests to the Discord API.
    ##
    ## * `pl` - stringified json payload.
    ## * `audit_reason` - audit log reason for any action
    ## * `mp` - multipart data which is used to attach files
    ## * `auth` - if authentication is needed.
    ## * `meth` - method of http request. definitely not illegal ;).
    if api.token == "Bot ":
        raise newException(Exception, "The token you specified was empty.")
    let route = endpoint.parseRoute(meth)

    if route notin api.endpoints:
        api.endpoints[route] = Ratelimit()

    var
        data: JsonNode
        error = ""

    let r = api.endpoints[route]
    while r.processing:
        await sleepAsync 0

    proc doreq() {.async.} =
        if invalid_requests >= 1500:
            raise newException(RestError,
                "You are sending too many invalid requests.")

        if global:
            await api.handleRoute(global)
        else:
            await api.handleRoute(false, route)

        let url = restBase & "v" & $api.restVersion & "/" & endpoint
        var respView: BasicResponse

        when defined(windowsNativeTls) and defined(windows):
            var headersTbl: Table[string, seq[string]]
            addHeader(headersTbl, "User-Agent", libAgent)
            addHeader(headersTbl, "Accept-Encoding", "identity")

            var bodyToSend = pl

            if mp != nil:
                type
                    MultipartEntry = object
                        nameLen: int
                        namePtr: pointer
                        bodyLen: int
                        bodyPtr: pointer
                        
                        # fileName is Option[string]. Layout: has(aligned 8), len(8), ptr(8) at 0x20
                        fileNameHas: int
                        fileNameLen: int
                        fileNamePtr: pointer
                        
                        # contentType is string (not Option). Layout: len(8), ptr(8) at 0x38
                        contentTypeLen: int
                        contentTypePtr: pointer
                        
                        fileSize: int64
                        isStream: int 
                        # Size is 88 bytes on this platform (Windows 64-bit, std/httpclient)

                    MultipartDataInternal = ref object
                        content: seq[MultipartEntry]

                proc makeString(len: int, p: pointer): string =
                    if len <= 0 or p == nil: return ""
                    # std/httpclient strings are pointers to [Len][Content].
                    # We need to skip the length header (8 bytes) to get to content.
                    let contentPtr = cast[pointer](cast[int](p) + 8)
                    result = newString(len)
                    copyMem(addr result[0], contentPtr, len)
                
                let mpi = cast[MultipartDataInternal](mp)
                let boundary = "---------------------------" & $rand(int.high)
                bodyToSend = ""

                for i in 0 ..< mpi.content.len:
                    let entry = addr mpi.content[i]
                    let nameStr = makeString(entry.nameLen, entry.namePtr)

                    var fileName = ""
                    if entry.fileNameLen > 0 and entry.fileNamePtr != nil:
                        fileName = makeString(entry.fileNameLen, entry.fileNamePtr)
                    
                    bodyToSend.add("--" & boundary & "\r\n")
                    bodyToSend.add("Content-Disposition: form-data; name=\"" & nameStr & "\"")
                    
                    if fileName.len > 0:
                        bodyToSend.add("; filename=\"" & fileName & "\"")
                    
                    bodyToSend.add("\r\n")
                    
                    if entry.contentTypeLen > 0:
                        let ct = makeString(entry.contentTypeLen, entry.contentTypePtr)
                        bodyToSend.add("Content-Type: " & ct & "\r\n")
                    
                    bodyToSend.add("\r\n")
                    
                    if entry.bodyLen > 0:
                         let bodyStr = makeString(entry.bodyLen, entry.bodyPtr)
                         bodyToSend.add(bodyStr)

                    bodyToSend.add("\r\n")

                    

                
                bodyToSend.add("--" & boundary & "--\r\n")
                addHeader(headersTbl, "Content-Type", "multipart/form-data; boundary=" & boundary)
            else:
                addHeader(headersTbl, "Content-Type", "application/json")

            addHeader(headersTbl, "Content-Length", $bodyToSend.len)

            if audit_reason != "":
                addHeader(headersTbl, "X-Audit-Log-Reason", encodeUrl(
                    audit_reason, usePlus = false
                ).replace(" ", "%20"))
            if auth:
                addHeader(headersTbl, "Authorization", api.token)

            log("Making request to " & meth & " " & url, (
                size: bodyToSend.len,
                reason: if audit_reason != "": audit_reason else: ""
            ))

            let fv = spawn winHttpRequest(meth, url, bodyToSend, headersTbl)

            while not isReady(fv):
                await sleepAsync 0
            respView = ^fv
        else:
            let client = newAsyncHttpClient(libAgent)

            if audit_reason != "":
                client.headers["X-Audit-Log-Reason"] = encodeUrl(
                    audit_reason, usePlus = false
                ).replace(" ", "%20")
            if auth:
                client.headers["Authorization"] = api.token

            client.headers["Content-Type"] = "application/json"
            client.headers["Content-Length"] = $pl.len
            client.headers["Accept-Encoding"] = "identity"

            log("Making request to " & meth & " " & url, (
                size: pl.len,
                reason: if audit_reason != "": audit_reason else: ""
            ))

            let req = client.request(url, parseEnum[HttpMethod](meth),
                        pl, multipart=mp)

            if not (await req.withTimeout(20_000)):
                log("Request is taking longer than 20s. Retrying request...")
                client.close()
                await doreq()

            try:
                let resp = await req
                respView = await resp.toBasicResponse()
            except:
                r.processing = false
                client.close()
                raise

            client.close()

        log("Got response.")

        let
            retry_header = getHeader(respView.headers,
                "X-RateLimit-Reset-After", "0.125").parseFloat
            status = respView.status
            fin = "[" & $status.int & "] "

        if retry_header > r.retry_after:
            r.retry_after = retry_header

        var detailederr = false
        if status >= Http300:
            error = fin & "Client error."

            if status != Http429: r.processing = false

            if status.is4xx:
                let contentType = getHeader(respView.headers, "content-type")
                if contentType.contains("application/json") and respView.body.len > 0:
                    try:
                        data = respView.body.parseJson
                    except:
                        data = nil

                    if not data.isNil:
                        detailederr = "code" in data and "message" in data

                case status:
                of Http400:
                    error = fin & "Bad request."
                    if not data.isNil and not detailederr:
                        error &= "\n" & data.pretty()
                of Http401:
                    error = fin & "Invalid authorization."
                    invalid_requests += 1
                of Http403:
                    error = fin & "Missing permissions/access."
                    invalid_requests += 1
                of Http404:
                    error = fin & "Not found."
                of Http429:
                    fatalErr = false
                    ratelimited = true

                    invalid_requests += 1

                    error = fin & "You are being rate-limited."
                    var retry: int

                    if data.isNil:
                        data = %*{"retry_after": 1.25}

                    if api.restVersion >= 8:
                        retry = data["retry_after"].getInt * 1000
                    else:
                        retry = int(data{"retry_after"}.getFloat(1.25) * 1000)

                    await sleepAsync retry

                    await doreq()
                else:
                    error = fin & "Unknown error"

                if detailederr and not data.isNil:
                    error &= "\n  * " & data.discordErrors()

            if status.is5xx:
                error = fin & "Internal Server Error."
                if status == Http503:
                    error = fin & "Service Unavailable."
                elif status == Http504:
                    error = fin & "Gateway timed out."

            if fatalErr:
                raise DiscordHttpError(
                    msg: error,
                    code: data{"code"}.getInt(status.int),
                    message: data{"message"}.getStr(
                        error[fin.len..^1].split("\n")[0]),
                    errors: %*data{"errors"}.getFields
                )
            else:
                echo error

        if status.is2xx:
            let contentType = getHeader(respView.headers, "content-type")
            if contentType.contains("application/json") and respView.body.len > 0:
                log("Awaiting for body to be parsed")
                data = respView.body.parseJson
            else:
                data = nil

            if invalid_requests > 0: invalid_requests -= 250

        let headerLimited = getHeader(respView.headers,
            "X-RateLimit-Remaining", "0") == "0"

        if headerLimited:
            if respView.headers.hasKey("x-ratelimit-global"):
                global = true
                global_retry_after = r.retry_after
                ratelimited = true
                r.ratelimited = true

                await api.handleRoute(global)
            else:
                global = false
                r.ratelimited = true
                await api.handleRoute(false, route)

        r.processing = false
    try:
        r.processing = true
        await doreq()
        log("Request has finished.")

        result = data
    except:
        raise

proc append*(mpd: var MultipartData;
        attachments: seq[Attachment];
        pl: var JsonNode; is_interaction = false) =
    ## Appends discord attachment items to multipart data.
    ## Internal use only, but you can use it if you want.

    if mpd.isNil: mpd = newMultipartData()

    var asgn = if is_interaction: pl["data"] else: pl
    asgn["attachments"] = %[]
    for i, a in attachments:
        if a.id == "": a.id = $i
        asgn["attachments"].add %a

    for i, a in attachments:
        var
            contenttype = ""
            body = a.file
            name = "files[" & $i & "]"

        softassert a.filename != "", "Attachment name needs to be provided."

        let att = splitFile(a.filename)

        if att.ext != "":
            let ext = att.ext[1..high(att.ext)]
            contenttype = newMimetypes().getMimetype(ext)

        if body == "": body = readFile(a.filename)
        mpd.add(name, body, a.filename, contenttype, useStream=false)

    mpd.add("payload_json", $pl, contentType = "application/json")

proc append*(mpd: var MultipartData;
        files: seq[DiscordFile];
        pl: var JsonNode) =
    ## Appends discord file items to multipart data.
    ## Internal use only, but you can use it if you want.
    if mpd.isNil: mpd = newMultipartData()

    for file in files:
        var contenttype = ""
        softassert file.name != "", "file name needs to be provided."

        let fil = splitFile(file.name)

        if fil.ext != "":
            let ext = fil.ext[1..high(fil.ext)]
            contenttype = newMimetypes().getMimetype(ext)

        if file.body == "": file.body = readFile(file.name)
        mpd.add(fil.name, file.body, file.name, contenttype, useStream=false)

    mpd.add("payload_json", $pl, contentType = "application/json")