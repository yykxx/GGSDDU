/* Copyright (C) Xingxing Ke 
 * All rights reserved.
 */

#ifndef _COMMIOCP_H
#define _COMMIOCP_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/* fd type */
enum {
    COMM_UNKNOWN,
    COMM_TCP,
    COMM_UDP,
    COMM_FILE
};

typedef PVOID COMMIOCP_HANDLE;
typedef PVOID COMMFD_HANDLE;

/* create allocate ctx, allocate ctx pass to COMM_ALLOC */
typedef PVOID (*COMM_ALLOC_CTX_CREATE)(size_t n, PVOID UserData);

/* close allocate ctx */
typedef VOID (*COMM_ALLOC_CTX_CLOSE)(PVOID Ctx, PVOID UserData);

/* allocate memory from ctx */
typedef PVOID (*COMM_ALLOC)(PVOID Ctx);

/* free memory to ctx */
typedef VOID (*COMM_FREE)(PVOID Ptr, PVOID Ctx);

/* on failure -- AcceptCB(UserData, INVALID_SOCKET, NULL, NULL) */
typedef VOID (*ACCEPT_CALLBACK)(PVOID, SOCKET, PSOCKADDR_IN, PSOCKADDR_IN);

/* ConnectCB(UserData, Fd, TRUE/FALSE) */
typedef VOID (*CONNECT_CALLBACK)(PVOID, COMMFD_HANDLE, BOOL);

/* ReadCB(UserData, Fd, ReadBuf, len) */
typedef VOID (*READ_CALLBACK)(PVOID, COMMFD_HANDLE, LPVOID, DWORD);

/* WriteCB(UserData, Fd, WriteBuf, len) */
typedef VOID (*WRITE_CALLBACK)(PVOID, COMMFD_HANDLE, LPCVOID, DWORD);

/* TaskCB(UserData) */
typedef VOID (*POST_TASK_ROUTINE)(PVOID);

/* global init 
 * return TRUE -- success, else error
 */
BOOL 
CommIOCPInit(
    VOID
    );

/* global destroy 
 * return void
 */
VOID
CommIOCPDestroy(
    VOID
    );

/* create CommIOCP handle
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
    );

/* close CommIOCP handle
 * @Handle -- IOCP object
 * return void
 */
VOID 
CommIOCPClose(
    COMMIOCP_HANDLE Handle
    );

/* open an common fd (tcp socket) and associate with IOCP
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
    );

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
    );

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
    );

/* assosicate a native handle with IOCP and return COMMFD obj
 * @Handle -- IOCP object
 * @Sock -- tcp socket
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPAssociateTcp(
    COMMIOCP_HANDLE Handle,
    SOCKET Sock
    );

/* assosicate a native handle with IOCP and return COMMFD obj
 * @Handle -- IOCP object
 * @Sock -- udp socket
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPAssociateUdp(
    COMMIOCP_HANDLE Handle,
    SOCKET Sock
    );

/* assosicate a native handle with IOCP and return COMMFD obj
 * @Handle -- IOCP object
 * @Sock -- file handle
 * return NULL -- error
 */
COMMFD_HANDLE 
CommIOCPAssociateFile(
    COMMIOCP_HANDLE Handle,
    HANDLE Sock
    );

/* destroy common fd
 * @Handle -- common fd to destroy
 * return TRUE -- success, else error
 */
BOOL
CommIOCPCloseFD(
    COMMFD_HANDLE Handle
    );

/* polling IOCP
 * Handle -- IOCP object
 * @Timeout -- time out value of Waiting IO Complete Notification
 * return 0 -- success, 1 -- timeout, else error
 */
INT
CommIOCPPoll(
    COMMIOCP_HANDLE Handle,
    DWORD Timeout
    );

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
    );

/* connect operation on tcp common fd
 * @Handle -- the common fd
 * @Peer -- remote host
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
    );

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
    );

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
    );

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
    );

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
    );

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
    );

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
    );

/* get file handle
 * @Handle -- COMMFD_HANDLE
 * return INVALID_HANDLE_VALUE on error, else success
 */
HANDLE 
CommIOCPGetNativeFileHandle(
    COMMFD_HANDLE Handle
    );

/* get socket handle
 * @Handle -- COMMFD_HANDLE
 * return INVALID_SOCKET on error, else success
 */
SOCKET 
CommIOCPGetNativeSocket(
    COMMFD_HANDLE Handle
    );

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
    );

/* get the assosicated COMMIOCP object handle
 * @Handle -- COMMFD_HANDLE
 * return a valid COMMIOCP_HANDLE
 */
COMMIOCP_HANDLE
CommIOCPGetIOCPFromFD(
    COMMFD_HANDLE Handle
    );

/* get type of COMMFD object
 * @Handle -- COMMFD_HANDLE
 * return COMM_TCP, COMM_UDP, COMM_FILE
 */
INT
CommIOCPGetFDType(
    COMMFD_HANDLE Handle
    );

#ifdef __cplusplus
}
#endif

#endif
