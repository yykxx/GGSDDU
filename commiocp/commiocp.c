/* Copyright (C) Xingxing Ke 
 * All rights reserved.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#if 0
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#endif

#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <intrin.h>

#include "commiocp.h"

#pragma comment(lib, "ws2_32")

enum {
    IO_SOCK_READ,
    IO_SOCK_WRITE,
    IO_SOCK_CONNECT,
    IO_SOCK_ACCEPT,
    IO_FILE_READ,
    IO_FILE_WRITE,
    IO_TASK
};

#define ADDRLEN (sizeof(SOCKADDR_IN) + 16)

typedef struct _COMMIOCP {
    HANDLE IOCP;
    COMM_ALLOC_CTX_CLOSE AllocCtxClose;
    COMM_ALLOC Alloc;
    COMM_FREE Free;
    PVOID UserData;
    PVOID IOCPAllocCtx;
    PVOID FileIOCtxAllocCtx;
    PVOID SocketIOCtxAllocCtx;
    PVOID FDAllocCtx;
    PVOID ConnectCtxAllocCtx;
    PVOID AcceptCtxAllocCtx;
    PVOID TaskAllocCtx;
} COMMIOCP, *PCOMMIOCP;
typedef const struct _COMMIOCP *PCCOMMIOCP;

typedef struct _COMMFD {
    PCOMMIOCP CommIOCP;
    union {
        SOCKET Socket;
        HANDLE File;
    } Handle;
    volatile LONG RefCount;
    BYTE Type;
} COMMFD, *PCOMMFD;
typedef const struct _COMMFD *PCCOMMFD;

typedef struct _COMM_IO_CTX {
    OVERLAPPED OL;
    union {
        READ_CALLBACK Read;
        WRITE_CALLBACK Write;
        CONNECT_CALLBACK Connect;
        ACCEPT_CALLBACK Accept;
        POST_TASK_ROUTINE Routine;
    } Callback;
    PVOID Args;
    BYTE Type;
} COMM_IO_CTX, *PCOMM_IO_CTX;
typedef const struct _COMM_IO_DATA *PCCOMM_IO_DATA;

typedef struct _COMM_FILE_IO_CTX {
    COMM_IO_CTX Data;
    union {
        LPVOID Read;
        LPCVOID Write;
    } Buffer;
} COMM_FILE_IO_CTX, *PCOMM_FILE_IO_CTX;
typedef const struct _COMM_FILE_IO_CTX *PCCOMM_FILE_IO_CTX;

typedef struct _COMM_SOCKET_IO_CTX {
    COMM_IO_CTX Data;
    WSABUF WSABuffer;
} COMM_SOCKET_IO_CTX, *PCOMM_SOCKET_IO_CTX;
typedef const struct _COMM_SOCKET_IO_CTX *PCCOMM_SOCKET_IO_CTX;

typedef struct _COMM_CONNECT_CTX {
    COMM_IO_CTX Data;
    PCOMMFD FD;
} COMM_CONNECT_CTX, *PCOMM_CONNECT_CTX;
typedef const struct _COMM_CONNECT_CTX *PCCOMM_CONNECT_CTX;

typedef struct _COMM_ACCEPT_CTX {
    COMM_IO_CTX Data;
    PCOMMIOCP CommIOCP;
    SOCKET ClientSock;
    BYTE AddrBuffer[ADDRLEN + ADDRLEN];
} COMM_ACCEPT_CTX, *PCOMM_ACCEPT_CTX;
typedef const struct _COMM_ACCEPT_CTX *PCCOMM_ACCEPT_CTX;

typedef struct _COMM_TASK_PROC {
    COMM_IO_CTX Data;
} COMM_TASK_PROC, *PCOMM_TASK_PROC;
typedef const struct _COMM_TASK_PROC *PCCOMM_TASK_PROC;

#define LOG_ERROR(fmt, ...)
#define LOG_TRACE(fmt, ...)
#define LOG_DEBUG(fmt, ...)

static LPFN_ACCEPTEX AcceptExPtr = NULL;
static LPFN_CONNECTEX ConnectExPtr = NULL;
static LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockAddrsPtr = NULL;

static BOOL 
CommIOCPAssociate(
    PCOMMFD Commfd
    )
{
    PCCOMMIOCP CommIOCP = Commfd->CommIOCP;
    HANDLE IOCP = CommIOCP->IOCP;
    HANDLE Handle = (HANDLE)Commfd->Handle.Socket;
    HANDLE Ret = CreateIoCompletionPort(Handle, IOCP, (ULONG_PTR)Commfd, 0);
    if (Ret != IOCP) {
        LOG_ERROR("CreateIoCompletionPort failed [%d]", GetLastError());
        return (FALSE);
    }
    return (TRUE);
}

static PCOMMFD 
CommIOCPFDCreate(
    COMMIOCP_HANDLE Handle,
    SOCKET Socket, 
    INT Type
    )
{
    PCOMMIOCP CommIOCP = (PCOMMIOCP)Handle;
    PCOMMFD Commfd = (PCOMMFD)CommIOCP->Alloc(CommIOCP->FDAllocCtx);
    if (Commfd) {
        memset(Commfd, 0, sizeof(*Commfd));
        Commfd->Handle.Socket = Socket;
        Commfd->Type = Type;
        Commfd->CommIOCP = CommIOCP;
    } else {
        LOG_ERROR("alloc fd failed");
    }
    return (Commfd);
}

static VOID 
CommIOCPFDDestroy(
    PCOMMFD Commfd
    )
{
    PCOMMIOCP CommIOCP = Commfd->CommIOCP;

    switch (Commfd->Type) {
    case COMM_TCP:
    case COMM_UDP:
        if (INVALID_SOCKET != Commfd->Handle.Socket) {
            closesocket(Commfd->Handle.Socket);
            Commfd->Handle.Socket = INVALID_SOCKET;
        }
        break;
    case COMM_FILE:
        if (INVALID_HANDLE_VALUE != Commfd->Handle.File) {
            CloseHandle(Commfd->Handle.File);
            Commfd->Handle.File = INVALID_HANDLE_VALUE;
        }
        break;
    }

    CommIOCP->Free(Commfd, CommIOCP->FDAllocCtx);
}

static __inline VOID
CommIOCPFDAddRef(
    PCOMMFD Commfd
    )
{
    InterlockedIncrement(&Commfd->RefCount);
}

static __inline VOID
CommIOCPFDRelease(
    PCOMMFD Commfd
    )
{
    if (InterlockedDecrement(&Commfd->RefCount) == 0) {
        CommIOCPFDDestroy(Commfd);
    }
}

static VOID
CommIOCPCloseFDTask(
    PVOID UserData
    )
{
    PCOMMFD Commfd = (PCOMMFD)UserData;
    PCCOMMIOCP CommIOCP = Commfd->CommIOCP;

    CommIOCPFDRelease(Commfd);

    switch (Commfd->Type) {
    case COMM_TCP:
    case COMM_UDP:
        if (INVALID_SOCKET != Commfd->Handle.Socket) {
            closesocket(Commfd->Handle.Socket);
            Commfd->Handle.Socket = INVALID_SOCKET;
        }
        break;

    case COMM_FILE:
        if (INVALID_HANDLE_VALUE != Commfd->Handle.File) {
            CloseHandle(Commfd->Handle.File);
            Commfd->Handle.File = INVALID_HANDLE_VALUE;
        }
        break;

    default:
        LOG_ERROR("unknown fd type [%d]", Commfd->Type);
        break;
    }

    CommIOCPFDRelease(Commfd);
}

static PCOMM_IO_CTX
CommIOCPIOCtxCreate(
    PCOMMIOCP CommIOCP,
    INT Type
    )
{
    PCOMM_IO_CTX Data;
    switch (Type) {
    case IO_FILE_READ:
        Data = CommIOCP->Alloc(CommIOCP->FileIOCtxAllocCtx);
        break;
    case IO_FILE_WRITE:
        Data = CommIOCP->Alloc(CommIOCP->FileIOCtxAllocCtx);
        break;
    case IO_SOCK_ACCEPT:
        Data = CommIOCP->Alloc(CommIOCP->AcceptCtxAllocCtx);
        break;
    case IO_SOCK_CONNECT:
        Data = CommIOCP->Alloc(CommIOCP->ConnectCtxAllocCtx);
        break;
    case IO_SOCK_READ:
        Data = CommIOCP->Alloc(CommIOCP->SocketIOCtxAllocCtx);
        break;
    case IO_SOCK_WRITE:
        Data = CommIOCP->Alloc(CommIOCP->SocketIOCtxAllocCtx);
        break;
    default:
        LOG_ERROR("bad io type [%d]", Type);
        return (NULL);
    }
    if (Data != NULL) {
        Data->Type = Type;
    } else {
        LOG_ERROR("alloc io ctx [%d] failed", Type);
    }
    return Data;
}

static VOID 
CommIOCPIOCtxDestroy(
    PCOMMIOCP CommIOCP,
    PCOMM_IO_CTX IOData
    )
{
    switch (IOData->Type) {
    case IO_FILE_READ:
        CommIOCP->Free(IOData, CommIOCP->FileIOCtxAllocCtx);
        break;
    case IO_FILE_WRITE:
        CommIOCP->Free(IOData, CommIOCP->FileIOCtxAllocCtx);
        break;
    case IO_SOCK_ACCEPT:
        CommIOCP->Free(IOData, CommIOCP->AcceptCtxAllocCtx);
        break;
    case IO_SOCK_CONNECT:
        CommIOCP->Free(IOData, CommIOCP->ConnectCtxAllocCtx);
        break;
    case IO_SOCK_READ:
        CommIOCP->Free(IOData, CommIOCP->SocketIOCtxAllocCtx);
        break;
    case IO_SOCK_WRITE:
        CommIOCP->Free(IOData, CommIOCP->SocketIOCtxAllocCtx);
        break;
    default:
        LOG_ERROR("bad io data type [%d]", IOData->Type);
        break;
    }
}

static BOOL
CommIOCPConnectProcess(PCOMM_IO_CTX Type)
{
    INT Seconds = -1, Err;
    INT Bytes = sizeof(Seconds);
    PCOMM_CONNECT_CTX Ctx = CONTAINING_RECORD(Type, COMM_CONNECT_CTX, Data);
    SOCKET Sock = Ctx->FD->Handle.Socket;
    PCOMMIOCP CommIOCP = Ctx->FD->CommIOCP;

    setsockopt(Sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    Err = getsockopt(Sock, SOL_SOCKET, SO_CONNECT_TIME, (char *)&Seconds, &Bytes);

    if (Err == NO_ERROR && Seconds != -1) {
        Ctx->Data.Callback.Connect(Ctx->Data.Args, Ctx->FD, TRUE);
    } else {
        Ctx->Data.Callback.Connect(Ctx->Data.Args, Ctx->FD, FALSE);
    }

    CommIOCPIOCtxDestroy(CommIOCP, &Ctx->Data);
    return (TRUE);
}

static BOOL
CommIOCPAcceptProcess(PCOMM_IO_CTX Type)
{
    PCOMM_ACCEPT_CTX Ctx = CONTAINING_RECORD(Type, COMM_ACCEPT_CTX, Data);
    PCOMMIOCP CommIOCP = Ctx->CommIOCP;
    SOCKET Sock = Ctx->ClientSock;
    INT Err;

    Err = setsockopt(Sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&Sock, sizeof(Sock));

    if (Err != SOCKET_ERROR) {
        INT LocalLen, RemoteLen;
        PSOCKADDR Local = NULL, Remote = NULL;

        GetAcceptExSockAddrsPtr(Ctx->AddrBuffer, 0, ADDRLEN, ADDRLEN, &Local, &LocalLen, &Remote, &RemoteLen);
        Ctx->Data.Callback.Accept(Ctx->Data.Args, Sock, (PSOCKADDR_IN)Local, (PSOCKADDR_IN)Remote);
    } else {
        /* failed, pass NULL to callback */
        Ctx->Data.Callback.Accept(Ctx->Data.Args, INVALID_SOCKET, NULL, NULL);
        closesocket(Sock);
    }
    
    CommIOCPIOCtxDestroy(CommIOCP, &Ctx->Data);
    return (TRUE);
}

static SOCKET
CommIOCPCreateSocket(
    IN_ADDR Addr,
    INT Port,
    INT Backlog,
    INT Type,
    BOOL ReuseAddr
)
{
    SOCKET Socket;

    switch (Type) {
    case COMM_TCP:
        Socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        break;
    case COMM_UDP:
        Socket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        break;
    default:
        LOG_ERROR("invalid socket type [%d]", Type);
        return (INVALID_SOCKET);
    }

    if (Socket == INVALID_SOCKET) {
        LOG_ERROR("invalid socket");
        return (INVALID_SOCKET);
    }

    if (Port >= 0 && Port <= 65535) {
        SOCKADDR_IN AddrIn;

        AddrIn.sin_family = AF_INET;
        AddrIn.sin_addr = Addr;
        AddrIn.sin_port = htons(Port);

        setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (char *)&ReuseAddr, sizeof(ReuseAddr));

        if (bind(Socket, (SOCKADDR *)&AddrIn, sizeof(AddrIn)) == SOCKET_ERROR) {
            LOG_ERROR("bind failed [%d]", WSAGetLastError());
            closesocket(Socket);
            return (INVALID_SOCKET);
        }
    } else {
        SOCKADDR_IN Local;

        Local.sin_family = AF_INET;
        Local.sin_addr.s_addr = htonl(ADDR_ANY);
        Local.sin_port = htons(0);

        if (bind(Socket, (PSOCKADDR)&Local, sizeof(Local)) == SOCKET_ERROR) {
            LOG_ERROR("bind failed [%d]", WSAGetLastError());
            closesocket(Socket);
            return (INVALID_SOCKET);
        }
    }

    if (Backlog > 0 && listen(Socket, Backlog) == SOCKET_ERROR) {
        LOG_ERROR("listen failed [%d]", WSAGetLastError());
        closesocket(Socket);
        return (INVALID_SOCKET);
    }

    return (Socket);
}

static PCOMMFD
CommIOCPOpenFDSocket(
    COMMIOCP_HANDLE Handle,
    IN_ADDR Addr,
    INT Port,
    INT Backlog,
    INT Type,
    BOOL Assocate,
    BOOL ReuseAddr
)
{
    SOCKET Socket;
    PCOMMFD Commfd = NULL;
    PCOMMIOCP CommIOCP = (PCOMMIOCP)Handle;

    Socket = CommIOCPCreateSocket(Addr, Port, Backlog, Type, ReuseAddr);
    if (Socket == INVALID_SOCKET) {
        return (NULL);
    }

    Commfd = CommIOCPFDCreate(CommIOCP, Socket, Type);
    if (!Commfd) {
        closesocket(Socket);
        return (NULL);
    }

    if (Assocate && CommIOCPAssociate(Commfd)) {
        LOG_ERROR("associate with IOCP failed");
        CommIOCPFDDestroy(Commfd);
        return (NULL);
    }

    return (Commfd);
}

/* global init
 * return TRUE -- success, else error
 */
BOOL
CommIOCPInit(
    VOID
    )
{
    INT Err, LastError;
    DWORD Bytes;
    SOCKET Socket;
    IN_ADDR addr;
    GUID ConnectexGUID = WSAID_CONNECTEX;
    GUID AcceptExGUID = WSAID_ACCEPTEX;
    GUID GetAcceptExSockaddrsGUID = WSAID_GETACCEPTEXSOCKADDRS;

    addr.s_addr = INADDR_ANY;

    Socket = CommIOCPCreateSocket(addr, 0, 0, COMM_TCP, FALSE);
    if (Socket == INVALID_SOCKET) {
        return (FALSE);
    }

    Err = WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &ConnectexGUID, sizeof(ConnectexGUID),
                   &ConnectExPtr, sizeof(ConnectExPtr),
                   &Bytes, NULL, NULL);

    LastError = WSAGetLastError();
    
    closesocket(Socket);

    if (Err == SOCKET_ERROR || !ConnectExPtr) {
        LOG_ERROR("Get ConnectEx failed [%d]", LastError);
        return (FALSE);
    }

    for (int i = 10000; i < 65535; i++) {
        Socket = CommIOCPCreateSocket(addr, i, 10, COMM_TCP, FALSE);
        if (Socket != INVALID_SOCKET) {
            break;
        }
    }

    Err = WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, 
                   &AcceptExGUID, sizeof(AcceptExGUID),
                   &AcceptExPtr, sizeof(AcceptExPtr),
                   &Bytes, NULL, NULL);

    LastError = WSAGetLastError();

    if (Err == SOCKET_ERROR || !AcceptExPtr) {
        LOG_ERROR("Get AcceptEx failed [%d]", LastError);
        closesocket(Socket);
        return (FALSE);
    }

    Err = WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &GetAcceptExSockaddrsGUID, sizeof(GetAcceptExSockaddrsGUID),
                   &GetAcceptExSockAddrsPtr, sizeof(GetAcceptExSockAddrsPtr),
                   &Bytes, NULL, NULL);

    LastError = WSAGetLastError();

    closesocket(Socket);

    if (Err == SOCKET_ERROR || !GetAcceptExSockAddrsPtr) {
        LOG_ERROR("Get GetAcceptExSockAddrs failed [%d]", LastError);
        return (FALSE);
    }

    return (TRUE);
}

/* global destroy
 * return void
 */
VOID
CommIOCPDestroy(
    VOID
    )
{
}

/* init IOCP
 * @CreateAllocCtx -- create allocate ctx, NULL for default
 * @CloseAllocCtx -- close allocate ctx, NULL for default
 * @Alloc -- allocate memory, NULL for default
 * @Free -- free memory, NULL for default
 * @UserData -- argument pass to AllocInit and AllocUninit
 * return NULL -- error, else success
 */
COMMIOCP_HANDLE
CommIOCPCreate(
    COMM_ALLOC_CTX_CREATE CreateAllocCtx,
    COMM_ALLOC_CTX_CLOSE CloseAllocCtx,
    COMM_ALLOC Alloc,
    COMM_FREE Free,
    PVOID UserData
    )
{
    PCOMMIOCP CommIOCP;
    PVOID IOCPAllocCtx;

    if (!CreateAllocCtx || !CloseAllocCtx || !Alloc || !Free) {
        LOG_ERROR("bad args");
        return (NULL);
    }

    IOCPAllocCtx = CreateAllocCtx(sizeof(*CommIOCP), UserData);

    CommIOCP = (PCOMMIOCP)Alloc(IOCPAllocCtx);
    if (!CommIOCP) {
        LOG_ERROR("alloc failed");
        return (NULL);
    }

    memset(CommIOCP, 0, sizeof(COMMIOCP));
    CommIOCP->IOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);

    if (!CommIOCP->IOCP) {
        LOG_ERROR("CreateIoCompletionPort failed [%d]", GetLastError());
        Free(CommIOCP, IOCPAllocCtx);
        CloseAllocCtx(IOCPAllocCtx, UserData);
        return (NULL);
    }

    CommIOCP->AllocCtxClose = CloseAllocCtx;
    CommIOCP->UserData = UserData;
    CommIOCP->Alloc = Alloc;
    CommIOCP->Free = Free;
    CommIOCP->IOCPAllocCtx = IOCPAllocCtx;
    CommIOCP->FileIOCtxAllocCtx = CreateAllocCtx(sizeof(COMM_FILE_IO_CTX), UserData);
    CommIOCP->SocketIOCtxAllocCtx = CreateAllocCtx(sizeof(COMM_SOCKET_IO_CTX), UserData);
    CommIOCP->FDAllocCtx = CreateAllocCtx(sizeof(COMMFD), UserData);
    CommIOCP->ConnectCtxAllocCtx = CreateAllocCtx(sizeof(COMM_CONNECT_CTX), UserData);
    CommIOCP->AcceptCtxAllocCtx = CreateAllocCtx(sizeof(COMM_ACCEPT_CTX), UserData);
    CommIOCP->TaskAllocCtx = CreateAllocCtx(sizeof(COMM_TASK_PROC), UserData);
    return (CommIOCP);
}

/* destroy IOCP
 * @Handle -- IOCP object
 * return void
 */
VOID 
CommIOCPClose(
    COMMIOCP_HANDLE Handle
    )
{
    PCOMMIOCP CommIOCP = (PCOMMIOCP)Handle;
    COMM_ALLOC_CTX_CLOSE AllocCtxClose = CommIOCP->AllocCtxClose;
    PVOID IOCPAllocCtx = CommIOCP->IOCPAllocCtx;
    PVOID UserData = CommIOCP->UserData;

    if (!CommIOCP) {
        LOG_ERROR("bad args");
        return;
    }

    if (CommIOCP->IOCP) {
        CloseHandle(CommIOCP->IOCP);
        CommIOCP->IOCP = NULL;
    }
    if (CommIOCP->FDAllocCtx) {
        CommIOCP->AllocCtxClose(CommIOCP->FDAllocCtx, CommIOCP->UserData);
        CommIOCP->FDAllocCtx = NULL;
    }
    if (CommIOCP->FileIOCtxAllocCtx) {
        CommIOCP->AllocCtxClose(CommIOCP->FileIOCtxAllocCtx, CommIOCP->UserData);
        CommIOCP->FileIOCtxAllocCtx = NULL;
    }
    if (CommIOCP->SocketIOCtxAllocCtx) {
        CommIOCP->AllocCtxClose(CommIOCP->SocketIOCtxAllocCtx, CommIOCP->UserData);
        CommIOCP->SocketIOCtxAllocCtx = NULL;
    }
    if (CommIOCP->AcceptCtxAllocCtx) {
        CommIOCP->AllocCtxClose(CommIOCP->AcceptCtxAllocCtx, CommIOCP->UserData);
        CommIOCP->AcceptCtxAllocCtx = NULL;
    }
    if (CommIOCP->ConnectCtxAllocCtx) {
        CommIOCP->AllocCtxClose(CommIOCP->ConnectCtxAllocCtx, CommIOCP->UserData);
        CommIOCP->ConnectCtxAllocCtx = NULL;
    }
    if (CommIOCP->TaskAllocCtx) {
        CommIOCP->AllocCtxClose(CommIOCP->TaskAllocCtx, CommIOCP->UserData);
        CommIOCP->TaskAllocCtx = NULL;
    }

    CommIOCP->Free(CommIOCP, CommIOCP->IOCPAllocCtx);

    if (IOCPAllocCtx) {
        AllocCtxClose(IOCPAllocCtx, UserData);
    }
}

/* open an common fd and associate with IOCP
 * @Handle -- IOCP object
 * @Addr -- bind local address
 * @Port -- port number, a valid port number indicate a bind operation
 * @Backlog -- socket listen queue length, -1 for client socket
 * @ReuseAddr -- SO_REUSEADDR
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPOpenFDTcp(
    COMMIOCP_HANDLE Handle,
    IN_ADDR Addr,
    INT Port, 
    INT Backlog, 
    BOOL ReuseAddr
    )
{
    return CommIOCPOpenFDSocket(Handle, Addr, Port, Backlog, COMM_TCP, TRUE, ReuseAddr);
}

/* open an common fd (udp socket) and associate with IOCP
 * @Handle -- IOCP object
 * @Addr -- bind local address
 * @Port -- port number, a valid port number indicate a bind operation
 * @ReuseAddr -- SO_REUSEADDR
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPOpenFDUdp(
    COMMIOCP_HANDLE Handle,
    IN_ADDR Addr,
    INT Port,
    BOOL ReuseAddr
    )
{
    return CommIOCPOpenFDSocket(Handle, Addr, Port, -1, COMM_UDP, TRUE, ReuseAddr);
}

/* open an common fd (file) and associate with IOCP
 * @Handle -- IOCP object
 * @FilePath -- file path
 * @AccessModeFlags -- GENERIC_READ, GENERIC_WRITE, etc
 * @ShareModeFlags -- FILE_SHARE_READ, FILE_SHARE_WRITE, etc
 * @CreationFlags -- CREATE_ALWAYS, CREATE_NEW, etc
 * @AttrFlags -- default set to FILE_FLAG_OVERLAPPED
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPOpenFDFile(
    COMMIOCP_HANDLE Handle,
    PCTSTR FilePath,
    DWORD AccessModeFlags,
    DWORD ShareModeFlags,
    DWORD CreationFlags,
    DWORD AttrFlags
    )
{
    HANDLE File;
    PCOMMFD Commfd;
    PCOMMIOCP CommIOCP = (PCOMMIOCP)Handle;

    AttrFlags |= FILE_FLAG_OVERLAPPED;

    File = CreateFile(FilePath, AccessModeFlags, ShareModeFlags, NULL, CreationFlags, AttrFlags, NULL);
    
    if (File == INVALID_HANDLE_VALUE) {
        LOG_ERROR("CreateFile failed [%d]", GetLastError());
        return (NULL);
    }

    Commfd = CommIOCPFDCreate(Handle, (SOCKET)File, COMM_FILE);
    if (Commfd && !CommIOCPAssociate(Commfd)) {
        LOG_ERROR("associate with IOCP failed");
        CommIOCPFDDestroy(Commfd);
        Commfd = NULL;
    }
    return (Commfd);
}

static __inline COMMFD_HANDLE 
CommIOCPAssociateNativeHandle(
    COMMIOCP_HANDLE Handle,
    SOCKET SockOrFile,
    INT Type
    )
{
    PCOMMFD Commfd = CommIOCPFDCreate(Handle, SockOrFile, Type);
    if (Commfd && !CommIOCPAssociate(Commfd)) {
        LOG_ERROR("associate with IOCP failed");
        CommIOCPFDDestroy(Commfd);
        Commfd = NULL;
    }
    return (Commfd);
}

/* assosicate a native handle with IOCP and return COMMFD obj
 * @Handle -- IOCP object
 * @Sock -- tcp socket
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPAssociateTcp(
    COMMIOCP_HANDLE Handle,
    SOCKET Sock
    )
{
    return CommIOCPAssociateNativeHandle(Handle, Sock, COMM_TCP);
}

/* assosicate a native handle with IOCP and return COMMFD obj
 * @Handle -- IOCP object
 * @Sock -- udp socket
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPAssociateUdp(
    COMMIOCP_HANDLE Handle,
    SOCKET Sock
    )
{
    return CommIOCPAssociateNativeHandle(Handle, Sock, COMM_UDP);
}

/* assosicate a native handle with IOCP and return COMMFD obj
 * @Handle -- IOCP object
 * @Sock -- file handle
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPAssociateFile(
    COMMIOCP_HANDLE Handle,
    HANDLE Sock
    )
{
    return CommIOCPAssociateNativeHandle(Handle, (SOCKET)Sock, COMM_FILE);
}

/* destroy common fd
 * @Handle -- common fd to destroy
 * return TRUE -- success, else error
 */
BOOL 
CommIOCPCloseFD(
    COMMFD_HANDLE Handle
    )
{
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Commfd) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCPFDAddRef(Commfd);
    if (!CommIOCPPostTask(Commfd->CommIOCP, CommIOCPCloseFDTask, Commfd)) {
        LOG_ERROR("post close task failed");
        return (FALSE);
    }

    return (TRUE);
}

/* polling IOCP
 * Handle -- IOCP object
 * @Timeout -- time out value of Waiting IO Complete Notification
 * return 0 -- success, 1 -- timeout, else error
 */
INT 
CommIOCPPoll(
    COMMIOCP_HANDLE Handle,
    DWORD Timeout
    )
{
    INT Ret = 0;
    BOOL Success;
    DWORD Bytes = 0;
    LPOVERLAPPED OverLap = NULL;
    PCOMMFD Commfd = NULL;
    PCOMM_IO_CTX IOCtx;
    PCOMMIOCP CommIOCP = (PCOMMIOCP)Handle;
    PCOMM_TASK_PROC Task;
    
    Success = GetQueuedCompletionStatus(CommIOCP->IOCP, &Bytes, (PULONG_PTR)&Commfd, &OverLap, Timeout);
    if (!Success && OverLap == NULL && Commfd == NULL) {
        return (1);
    }

    IOCtx = CONTAINING_RECORD(OverLap, COMM_IO_CTX, OL);
    if (IOCtx->Type == IO_TASK) {
        Task = CONTAINING_RECORD(IOCtx, COMM_TASK_PROC, Data);
        Task->Data.Callback.Routine(Task->Data.Args);
        CommIOCP->Free(Task, CommIOCP->TaskAllocCtx);
        return (0);
    }

    switch (IOCtx->Type) {
    case IO_SOCK_READ: {
        /* MSG_PARTIAL -- maybe we need to process this flag for UDP recv,
         * when sender send a large message and the buffer for recver is not
         * large enough, test flag to see whether MSG_PARTIAL is set or not
         * this flag could be get by syscall like WSAGetOverlappedResult
         */
        PCOMM_SOCKET_IO_CTX SockIOCtx = CONTAINING_RECORD(IOCtx, COMM_SOCKET_IO_CTX, Data);
        assert(IOCtx->Callback.Read != NULL);
        IOCtx->Callback.Read(IOCtx->Args, Commfd, SockIOCtx->WSABuffer.buf, Bytes);
        break;
    }

    case IO_SOCK_WRITE: {
        PCOMM_SOCKET_IO_CTX SockIOCtx = CONTAINING_RECORD(IOCtx, COMM_SOCKET_IO_CTX, Data);
        assert(IOCtx->Callback.Write != NULL);
        IOCtx->Callback.Write(IOCtx->Args, Commfd, SockIOCtx->WSABuffer.buf, Bytes);
        break;
    }

    case IO_FILE_READ: {
        PCOMM_FILE_IO_CTX FileIOCtx = CONTAINING_RECORD(IOCtx, COMM_FILE_IO_CTX, Data);
        assert(IOCtx->Callback.Read != NULL);
        IOCtx->Callback.Read(IOCtx->Args, Commfd, FileIOCtx->Buffer.Read, Bytes);
        break;
    }

    case IO_FILE_WRITE: {
        PCOMM_FILE_IO_CTX FileIOCtx = CONTAINING_RECORD(IOCtx, COMM_FILE_IO_CTX, Data);
        assert(IOCtx->Callback.Write != NULL);
        IOCtx->Callback.Write(IOCtx->Args, Commfd, FileIOCtx->Buffer.Write, Bytes);
        break;
    }

    case IO_SOCK_CONNECT: {
        CommIOCPConnectProcess(IOCtx);
        break;
    }

    case IO_SOCK_ACCEPT: {
        CommIOCPAcceptProcess(IOCtx);
        break;
    }

    default:
        LOG_ERROR("unknown IO type [%d]", IOCtx->Type);
        Ret = -1;
        break;
    }

    CommIOCPFDRelease(Commfd);
    
    if (IOCtx) {
        CommIOCPIOCtxDestroy(CommIOCP, IOCtx);
    }

    return (Ret);
}

/* accept operation on tcp common fd
 * @Handle -- the listen fd
 * @Callback -- callback function when accept successful
 * @Args -- arguments to callback
 * return TRUE -- success, else error
 */
BOOL
CommIOCPTcpAccept(
    COMMFD_HANDLE Handle, 
    ACCEPT_CALLBACK Callback, 
    PVOID Args
    )
{
    IN_ADDR Addr;
    DWORD Bytes;
    BOOL Succ;
    PCOMMIOCP CommIOCP;
    PCOMM_ACCEPT_CTX Ctx = NULL;
    PCOMMFD ListenFd = (PCOMMFD)Handle;
    SOCKET ClientSock, ListenSock;

    if (!Callback || !ListenFd || ListenFd->Type != COMM_TCP || ListenFd->Handle.Socket == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCP = ListenFd->CommIOCP;

    ListenSock = ListenFd->Handle.Socket;
    if (ListenSock == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    Addr.s_addr = INADDR_ANY;

    ClientSock = CommIOCPCreateSocket(Addr, -1, -1, COMM_TCP, FALSE);
    if (ClientSock == INVALID_SOCKET) {
        return (FALSE);
    }

    Ctx = (PCOMM_ACCEPT_CTX)CommIOCPIOCtxCreate(CommIOCP, IO_SOCK_ACCEPT);
    if (!Ctx) {
        LOG_ERROR("create accept context failed");
        closesocket(ClientSock);
        return (FALSE);
    }

    Ctx->Data.Args = Args;
    Ctx->Data.Callback.Accept = Callback;
    Ctx->ClientSock = ClientSock;
        
    CommIOCPFDAddRef(ListenFd);
    Succ = AcceptExPtr(ListenSock, ClientSock, Ctx->AddrBuffer, 0, ADDRLEN, ADDRLEN, &Bytes, &Ctx->Data.OL);

    if (!Succ && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("AcceptEx failed [%d]", WSAGetLastError());
        closesocket(ClientSock);
        CommIOCPIOCtxDestroy(CommIOCP, &Ctx->Data);
        CommIOCPFDRelease(ListenFd);
        return (FALSE);
    }

    return (TRUE);
}

/* connect operation on tcp common fd
 * @Handle -- the common fd
 * @Peer -- remote host
 * @Port -- the port number of remote host
 * @Callback -- callback function when accept successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL
CommIOCPTcpConnect(
    COMMFD_HANDLE Handle, 
    PSOCKADDR Peer, 
    INT PeerLen,
    CONNECT_CALLBACK Callback, 
    PVOID Args
    )
{
    DWORD Bytes = 0;
    BOOL Succ;
    PCOMMIOCP CommIOCP;
    PCOMM_CONNECT_CTX Ctx = NULL;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_TCP || Commfd->Handle.Socket == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCP = Commfd->CommIOCP;

    Ctx = (PCOMM_CONNECT_CTX)CommIOCPIOCtxCreate(CommIOCP, IO_SOCK_CONNECT);
    if (!Ctx) {
        LOG_ERROR("create connect context failed");
        return (FALSE);
    }

    Ctx->FD = Commfd;
    Ctx->Data.Callback.Connect = Callback;
    Ctx->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Succ = ConnectExPtr(Commfd->Handle.Socket, Peer, PeerLen, NULL, 0, &Bytes, &Ctx->Data.OL);

    if (!Succ && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("ConnectEx failed [%d]", WSAGetLastError());
        CommIOCPIOCtxDestroy(CommIOCP, &Ctx->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

 /* read operation on common fd (file)
 * @Handle -- the common fd
 * @Buffer -- data buffer
 * @BufferSize -- buffer size in bytes
 * @ReadOffset -- read offset
 * @Callback -- callback function when read successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL
CommIOCPFileRead(
    COMMFD_HANDLE Handle, 
    PBYTE Buffer, 
    DWORD BufferSize, 
    PULARGE_INTEGER ReadOffset,
    READ_CALLBACK Callback,
    PVOID Args
    )
{
    BOOL Succ;
    PCOMMIOCP CommIOCP;
    PCOMM_FILE_IO_CTX IOData;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_FILE || Commfd->Handle.File == INVALID_HANDLE_VALUE) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCP = Commfd->CommIOCP;

    IOData = (PCOMM_FILE_IO_CTX)CommIOCPIOCtxCreate(Commfd->CommIOCP, IO_FILE_READ);
    if (IOData == NULL) {
        LOG_ERROR("create file IO context failed");
        return (FALSE);
    }

    IOData->Buffer.Read = Buffer;
    IOData->Data.OL.Offset = ReadOffset->LowPart;
    IOData->Data.OL.OffsetHigh = ReadOffset->HighPart;
    IOData->Data.Callback.Read = Callback;
    IOData->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Succ = ReadFile(Commfd->Handle.File, Buffer, BufferSize, NULL, &IOData->Data.OL);

    if (!Succ && GetLastError() != ERROR_IO_PENDING) {
        LOG_ERROR("ReadFile failed [%d]", GetLastError());
        CommIOCPIOCtxDestroy(Commfd->CommIOCP, &IOData->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

/* write operation on common fd (file)
 * @Handle -- the common fd
 * @Buffer -- data buffer
 * @BufferSize -- size of data to write
 * @WriteOffset -- write offset
 * @Callback -- callback function when write successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL
CommIOCPFileWrite(
    COMMFD_HANDLE Handle, 
    PBYTE Buffer, 
    DWORD BufferSize, 
    PULARGE_INTEGER WriteOffset,
    WRITE_CALLBACK Callback,
    PVOID Args
    )
{
    BOOL Succ;
    PCOMMIOCP CommIOCP;
    PCOMM_FILE_IO_CTX IOData;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_FILE || Commfd->Handle.File == INVALID_HANDLE_VALUE) {
        LOG_ERROR("bad args");
        return (FALSE);
    }
    
    CommIOCP = Commfd->CommIOCP;

    IOData = (PCOMM_FILE_IO_CTX)CommIOCPIOCtxCreate(Commfd->CommIOCP, IO_FILE_WRITE);
    if (IOData == NULL) {
        LOG_ERROR("create file IO context failed");
        return (FALSE);
    }

    IOData->Buffer.Write = Buffer;
    IOData->Data.OL.Offset = WriteOffset->LowPart;
    IOData->Data.OL.OffsetHigh = WriteOffset->HighPart;
    IOData->Data.Callback.Write = Callback;
    IOData->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Succ = WriteFile(Commfd->Handle.File, Buffer, BufferSize, NULL, &IOData->Data.OL);

    if (!Succ && GetLastError() != ERROR_IO_PENDING) {
        LOG_ERROR("ReadFile failed [%d]", GetLastError());
        CommIOCPIOCtxDestroy(Commfd->CommIOCP, &IOData->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

/* read operation on common fd (tcp)
 * @Handle -- the common fd
 * @Buffer -- data buffer
 * @BufferSize -- buffer size in bytes
 * @Callback -- callback function when read successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL
CommIOCPTcpRead(
    COMMFD_HANDLE Handle, 
    PBYTE Buffer, 
    DWORD BufferSize, 
    READ_CALLBACK Callback,
    PVOID Args
    )
{
    INT Ret;
    PCOMMIOCP CommIOCP;
    DWORD Flags = 0, Bytes = 0;
    PCOMM_SOCKET_IO_CTX IOData;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_TCP || Commfd->Handle.Socket == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }
    
    CommIOCP = Commfd->CommIOCP;

    IOData = (PCOMM_SOCKET_IO_CTX)CommIOCPIOCtxCreate(Commfd->CommIOCP, IO_SOCK_READ);
    if (IOData == NULL) {
        LOG_ERROR("create socket IO context failed");
        return (FALSE);
    }

    IOData->WSABuffer.buf = (CHAR *)Buffer;
    IOData->WSABuffer.len = BufferSize;
    IOData->Data.Callback.Read = Callback;
    IOData->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Ret = WSARecv(Commfd->Handle.Socket, &IOData->WSABuffer, 1, &Bytes, &Flags, &IOData->Data.OL, NULL);

    if (Ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("WSARecv failed [%d]", WSAGetLastError());
        CommIOCPIOCtxDestroy(Commfd->CommIOCP, &IOData->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

/* write operation on common fd (tcp)
 * @Handle -- the common fd
 * @Buffer -- data buffer
 * @BufferSize -- size of data to write
 * @Callback -- callback function when write successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL
CommIOCPTcpWrite(
    COMMFD_HANDLE Handle, 
    PBYTE Buffer, 
    DWORD BufferSize, 
    WRITE_CALLBACK Callback,
    PVOID Args
    )
{
    INT Ret;
    PCOMMIOCP CommIOCP;
    DWORD Flags = 0, Bytes = 0;
    PCOMM_SOCKET_IO_CTX IOData;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_TCP || Commfd->Handle.Socket == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCP = Commfd->CommIOCP;

    IOData = (PCOMM_SOCKET_IO_CTX)CommIOCPIOCtxCreate(Commfd->CommIOCP, IO_SOCK_WRITE);
    if (IOData == NULL) {
        LOG_ERROR("create socket IO context failed");
        return (FALSE);
    }

    IOData->WSABuffer.buf = (CHAR *)Buffer;
    IOData->WSABuffer.len = BufferSize;
    IOData->Data.Callback.Write = Callback;
    IOData->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Ret = WSASend(Commfd->Handle.Socket, &IOData->WSABuffer, 1, &Bytes, Flags, &IOData->Data.OL, NULL);

    if (Ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("WSASend failed [%d]", WSAGetLastError());
        CommIOCPIOCtxDestroy(Commfd->CommIOCP, &IOData->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

/* read operation on common fd (udp)
 * @Handle -- the common fd
 * @Dst -- destination address information
 * @DstLen -- sizeof Dst
 * @Buffer -- data buffer
 * @BufferSize -- buffer size in bytes
 * @Callback -- callback function when read successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL 
CommIOCPUdpRead(
    COMMFD_HANDLE Handle, 
    PSOCKADDR Dst,
    PINT DstLen,
    PBYTE Buffer, 
    DWORD BufferSize, 
    READ_CALLBACK Callback,
    PVOID Args
    )
{
    INT Ret;
    PCOMMIOCP CommIOCP;
    DWORD Flags = MSG_PARTIAL, Bytes = 0;
    PCOMM_SOCKET_IO_CTX IOData;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_UDP || Commfd->Handle.Socket == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCP = Commfd->CommIOCP;
    
    IOData = (PCOMM_SOCKET_IO_CTX)CommIOCPIOCtxCreate(Commfd->CommIOCP, IO_SOCK_READ);
    if (IOData == NULL) {
        LOG_ERROR("create socket IO context failed");
        return (FALSE);
    }

    IOData->WSABuffer.buf = (CHAR *)Buffer;
    IOData->WSABuffer.len = BufferSize;
    IOData->Data.Callback.Read = Callback;
    IOData->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Ret = WSARecvFrom(Commfd->Handle.Socket, &IOData->WSABuffer, 1, &Bytes, &Flags, Dst, DstLen, &IOData->Data.OL, NULL);

    if (Ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("WSARecvFrom failed [%d]", WSAGetLastError());
        CommIOCPIOCtxDestroy(Commfd->CommIOCP, &IOData->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

/* write operation on common fd (udp)
 * @Handle -- the common fd
 * @Dst -- destination address information
 * @DstLen -- sizeof Dst
 * @Buffer -- data buffer
 * @BufferSize -- size of data to write
 * @Callback -- callback function when write successful
 * @Args -- argument to callback
 * return TRUE -- success, else error
 */
BOOL 
CommIOCPUdpWrite(
    COMMFD_HANDLE Handle, 
    PSOCKADDR Dst,
    INT DstLen,
    PBYTE Buffer, 
    DWORD BufferSize, 
    WRITE_CALLBACK Callback,
    PVOID Args
    )
{
    INT Ret;
    PCOMMIOCP CommIOCP;
    PCOMM_SOCKET_IO_CTX IOData;
    DWORD Flags = 0, Bytes = 0;
    PCOMMFD Commfd = (PCOMMFD)Handle;

    if (!Callback || !Commfd || Commfd->Type != COMM_UDP || Commfd->Handle.Socket == INVALID_SOCKET) {
        LOG_ERROR("bad args");
        return (FALSE);
    }

    CommIOCP = Commfd->CommIOCP;
    
    IOData = (PCOMM_SOCKET_IO_CTX)CommIOCPIOCtxCreate(Commfd->CommIOCP, IO_SOCK_WRITE);
    if (IOData == NULL) {
        LOG_ERROR("create socket IO context failed");
        return (FALSE);
    }

    IOData->WSABuffer.buf = (CHAR *)Buffer;
    IOData->WSABuffer.len = BufferSize;
    IOData->Data.Callback.Write = Callback;
    IOData->Data.Args = Args;

    CommIOCPFDAddRef(Commfd);
    Ret = WSASendTo(Commfd->Handle.Socket, &IOData->WSABuffer, 1, &Bytes, Flags, Dst, DstLen, &IOData->Data.OL, NULL);

    if (Ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG_ERROR("WSASendTo failed [%d]", WSAGetLastError());
        CommIOCPIOCtxDestroy(Commfd->CommIOCP, &IOData->Data);
        CommIOCPFDRelease(Commfd);
        return (FALSE);
    }

    return (TRUE);
}

/* get file handle
 * @Handle -- COMMFD_HANDLE
 * return NULL on error, else success
 */
HANDLE 
CommIOCPGetNativeFileHandle(
    COMMFD_HANDLE Handle
    )
{
    PCOMMFD Commfd = (PCOMMFD)Handle;
    if (Commfd && Commfd->Type == COMM_FILE) {
        return (Commfd->Handle.File);
    }
    return (INVALID_HANDLE_VALUE);
}

/* get socket handle
 * @Handle -- COMMFD_HANDLE
 * return NULL on error, else success
 */
SOCKET 
CommIOCPGetNativeSocket(
    COMMFD_HANDLE Handle
    )
{
    PCOMMFD Commfd = (PCOMMFD)Handle;
    if (Commfd && Commfd->Type == COMM_TCP || Commfd->Type == COMM_UDP) {
        return (Commfd->Handle.Socket);
    }
    return (INVALID_SOCKET);
}

/* post a task to IOCP, the Proc will be called in Poll thread
 * @Handle -- COMMIOCP_HANDLE
 * @Routine -- task routine
 * @Data -- agrument to Routine
 * return TRUE -- success, else error
 */
BOOL
CommIOCPPostTask(
    COMMIOCP_HANDLE Handle,
    POST_TASK_ROUTINE Routine,
    PVOID Data
    )
{
    PCOMM_TASK_PROC Task;
    PCOMMIOCP CommIOCP = (PCOMMIOCP)Handle;

    if (!CommIOCP) {
        LOG_ERROR("bad args");
        return (FALSE);
    }
       
    Task = (PCOMM_TASK_PROC)CommIOCPIOCtxCreate(CommIOCP, IO_TASK);
    if (!Task) {
        LOG_ERROR("alloc task failed");
        return (FALSE);
    }

    Task->Data.Callback.Routine = Routine;
    Task->Data.Args = Data;

    if (!PostQueuedCompletionStatus(CommIOCP->IOCP, 0, 0, &Task->Data.OL)) {
        LOG_ERROR("PostQueuedCompletionStatus failed [%d]", GetLastError());
        CommIOCPIOCtxDestroy(CommIOCP, &Task->Data);
        return (FALSE);
    }
    return (TRUE);
}

/* get the assosicated COMMIOCP object handle
 * @Handle -- COMMFD_HANDLE
 * return a valid COMMIOCP_HANDLE
 */
COMMIOCP_HANDLE
CommIOCPGetIOCPFromFD(
    COMMFD_HANDLE Handle
    )
{
    PCOMMIOCP CommIOCP = NULL;
    PCOMMFD Commfd = (PCOMMFD)Handle;
    if (Commfd) {
        CommIOCP = Commfd->CommIOCP;
    }
    return (CommIOCP);
}

/* get type of COMMFD object
 * @Handle -- COMMFD_HANDLE
 * return COMM_TCP, COMM_UDP, COMM_FILE
 */
INT
CommIOCPGetFDType(
    COMMFD_HANDLE Handle
    )
{
    INT Type = COMM_UNKNOWN;
    PCOMMFD Commfd = (PCOMMFD)Handle;
    if (Commfd) {
        Type = Commfd->Type;
    }
    return (Type);
}
