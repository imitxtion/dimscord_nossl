when defined(windowsNativeTls) and defined(windows):
    import winlean, unicode, uri, base64, random, strutils, asyncdispatch, threadpool
    import ./constants

    randomize()

    type
        HINTERNET* = pointer
        Opcode* = enum
            Text, Binary, Close
        FakeTcpSocket* = ref object
            closed*: bool
        Websocket* = ref object
            handle: HINTERNET
            session: HINTERNET
            connect: HINTERNET
            tcpSocket*: FakeTcpSocket
            closed: bool

    const
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
        WINHTTP_FLAG_SECURE = 0x00800000
        WINHTTP_QUERY_STATUS_CODE = 19
        WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
        WINHTTP_OPTION_DISABLE_FEATURE = 63
        WINHTTP_DISABLE_HTTP2 = 0x8
        WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET = 114
        WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE = 0'u32
        WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE = 1'u32
        WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE = 2'u32
        WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE = 3'u32
        WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE = 4'u32
        WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS = 1000'u16
        ERROR_SUCCESS = 0
        ERROR_IO_PENDING = 997
        ERROR_MORE_DATA = 234

    proc WinHttpOpen(userAgent: WideCString, accessType: int32, proxyName: pointer,
            proxyBypass: pointer, flags: uint32): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpOpen".}
    proc WinHttpCloseHandle(handle: HINTERNET): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpCloseHandle".}
    proc WinHttpConnect(session: HINTERNET, serverName: WideCString, serverPort: uint16,
            reserved: uint32): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpConnect".}
    proc WinHttpOpenRequest(connect: HINTERNET, verb: WideCString, objectName: WideCString,
            version: WideCString, referrer: WideCString, acceptTypes: pointer, flags: uint32): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpOpenRequest".}
    proc WinHttpSendRequest(request: HINTERNET, headers: WideCString, headersLength: int32,
            optional: pointer, optionalLength: int32, totalLength: int32, context: uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpSendRequest".}
    proc WinHttpReceiveResponse(request: HINTERNET, reserved: pointer): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpReceiveResponse".}
    proc WinHttpQueryHeaders(request: HINTERNET, infoLevel: uint32, name: pointer,
            buffer: pointer, bufferLength: ptr uint32, index: ptr uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpQueryHeaders".}
    proc WinHttpSetOption(handle: HINTERNET, option: uint32, buffer: pointer, bufferLength: uint32): bool {.stdcall, dynlib: "winhttp", importc: "WinHttpSetOption".}
    proc WinHttpWebSocketCompleteUpgrade(request: HINTERNET, reserved: pointer): HINTERNET {.stdcall, dynlib: "winhttp", importc: "WinHttpWebSocketCompleteUpgrade".}
    proc WinHttpWebSocketSend(websocket: HINTERNET, bufferType: uint32, buffer: pointer, length: uint32): int32 {.stdcall, dynlib: "winhttp", importc: "WinHttpWebSocketSend".}
    proc WinHttpWebSocketReceive(websocket: HINTERNET, buffer: pointer, length: uint32, bytesRead: ptr uint32, bufferType: ptr uint32): int32 {.stdcall, dynlib: "winhttp", importc: "WinHttpWebSocketReceive".}
    proc WinHttpWebSocketClose(websocket: HINTERNET, status: uint16, reason: WideCString, reasonLen: uint16): int32 {.stdcall, dynlib: "winhttp", importc: "WinHttpWebSocketClose".}

    proc isClosed*(tcp: FakeTcpSocket): bool = tcp.closed

    proc closeHandleSafe(h: var HINTERNET) =
        if h != nil:
            discard WinHttpCloseHandle(h)
            h = nil

    proc makeWebsocketKey(): string =
        var raw: array[16, byte]
        for i in 0 .. raw.high:
            raw[i] = rand(255).byte
        result = base64.encode(raw.toOpenArray(0, raw.high))

    proc winHttpReceiveWrapper(handle: HINTERNET, buf: pointer, len: uint32, bytesRead: ptr uint32, bufferType: ptr uint32): int32 {.gcsafe.} =
        WinHttpWebSocketReceive(handle, buf, len, bytesRead, bufferType)

    proc ensure(ok: bool, msg: string) =
        if not ok:
            raise newException(OSError, msg & " (" & $getLastError() & ")")

    proc newWebSocket*(url: string): Future[Websocket] {.async.} =
        let u = parseUri(url)
        let secure = u.scheme.toLowerAscii() == "wss"
        let port = if u.port.len > 0: uint16(parseInt(u.port)) else: (if secure: 443 else: 80)
        var path = if u.path.len == 0: "/" else: u.path
        if u.query.len > 0:
            path &= "?" & u.query

        var session = WinHttpOpen(newWideCString(libAgent), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0)
        ensure(not session.isNil, "WinHttpOpen failed" & " (" & $getLastError() & ")")
        var connect = WinHttpConnect(session, newWideCString(u.hostname), port, 0)
        ensure(not connect.isNil, "WinHttpConnect failed" & " (" & $getLastError() & ")")

        var request = WinHttpOpenRequest(connect, newWideCString("GET"), newWideCString(path), nil, nil, nil, if secure: WINHTTP_FLAG_SECURE else: 0)
        ensure(not request.isNil, "WinHttpOpenRequest failed" & " (" & $getLastError() & ")")

        let wsKey = makeWebsocketKey()
        var headers = "Upgrade: websocket\r\n" &
            "Connection: Upgrade\r\n" &
            "Sec-WebSocket-Version: 13\r\n" &
            "Sec-WebSocket-Key: " & wsKey & "\r\n" &
            "Host: " & u.hostname & "\r\n" &
            "User-Agent: " & libAgent & "\r\n"

        var disableHttp2 = WINHTTP_DISABLE_HTTP2.uint32
        let disableOk = WinHttpSetOption(session, WINHTTP_OPTION_DISABLE_FEATURE, addr disableHttp2, uint32(sizeof(disableHttp2)))
        if not disableOk:
            # Some WinHTTP builds return 12018 (incorrect handle type/not settable). Treat as best-effort.
            let err = getLastError()
            when defined(dimscordDebug):
                echo "WinHttpSetOption(DISABLE_HTTP2) best-effort skipped (", err, ")"
        ensure(WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nil, 0), "WinHttpSetOption(UPGRADE_TO_WEB_SOCKET) failed")

        ensure(WinHttpSendRequest(request, newWideCString(headers), -1, nil, 0, 0, 0), "WinHttpSendRequest failed" & " (" & $getLastError() & ")")
        ensure(WinHttpReceiveResponse(request, nil), "WinHttpReceiveResponse failed" & " (" & $getLastError() & ")")

        var statusCode: uint32 = 0
        var statusSize: uint32 = uint32(sizeof(uint32))
        ensure(WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER, nil, addr statusCode, addr statusSize, nil), "WinHttpQueryHeaders(status) failed" & " (" & $getLastError() & ")")
        if statusCode != 101:
            closeHandleSafe(request)
            closeHandleSafe(connect)
            closeHandleSafe(session)
            raise newException(OSError, "WebSocket upgrade failed with status " & $statusCode)

        var wsHandle = WinHttpWebSocketCompleteUpgrade(request, nil)
        ensure(not wsHandle.isNil, "WinHttpWebSocketCompleteUpgrade failed")
        discard WinHttpCloseHandle(request) # release request handle after upgrade

        result = Websocket(
            handle: wsHandle,
            session: session,
            connect: connect,
            tcpSocket: FakeTcpSocket(closed: false),
            closed: false
        )

    proc send*(ws: Websocket, payload: string, opcode: Opcode): Future[void] {.async.} =
        if ws.closed: return
        let bufferType = case opcode:
            of Text: WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE
            of Binary: WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE
            of Close: WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE
        let code = WinHttpWebSocketSend(ws.handle, bufferType, if payload.len > 0: unsafeAddr payload[0] else: nil, uint32(payload.len))
        if code != ERROR_SUCCESS:
            when defined(dimscordDebug):
                echo "WinWS: send failed, closing socket. Code: ", code
            ws.tcpSocket.closed = true
            ws.closed = true
            raise newException(OSError, "WinHttpWebSocketSend failed: " & $code)

    proc receivePacket*(ws: Websocket): Future[(Opcode, string)] {.async.} =
        if ws.closed:
            return (Close, "")

        var acc = newStringOfCap(8192)
        var buf = newString(8192)
        var bufferType: uint32 = 0
        while true:
            var read: uint32 = 0
            let fv = spawn winHttpReceiveWrapper(ws.handle, if buf.len > 0: addr buf[0] else: nil, uint32(buf.len), addr read, addr bufferType)
            while not isReady(fv):
                await sleepAsync 5 # Give 5ms to avoid tight loop
            let code = ^fv
            
            if code == ERROR_MORE_DATA:
                acc.add(buf[0 ..< int(read)])
                buf.setLen(buf.len * 2)
                continue
            elif code != ERROR_SUCCESS:
                when defined(dimscordDebug):
                    echo "WinWS: receive failed, closing socket. Code: ", code
                ws.tcpSocket.closed = true
                ws.closed = true
                raise newException(OSError, "WinHttpWebSocketReceive failed: " & $code)

            acc.add(buf[0 ..< int(read)])
            case bufferType
            of WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE, WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE:
                continue
            of WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE:
                return (Binary, acc)
            of WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE:
                return (Text, acc)
            of WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE:
                when defined(dimscordDebug):
                    echo "WinWS: Received close frame."
                ws.tcpSocket.closed = true
                ws.closed = true
                return (Close, acc)
            else:
                return (Binary, acc)

    proc close*(ws: Websocket) =
        if ws.closed: return
        when defined(dimscordDebug):
            echo "WinWS: Explicit close called."
        discard WinHttpWebSocketClose(ws.handle, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nil, 0)
        ws.closed = true
        ws.tcpSocket.closed = true
        closeHandleSafe(ws.handle)
        closeHandleSafe(ws.connect)
        closeHandleSafe(ws.session)
else:
    {.error: "winws.nim is only for windowsNativeTls builds.".}
