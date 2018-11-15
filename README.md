# eclib
easy c++ library for windows and linux(and ARM linux)<br>
eclib is easy to use, just include the .h file you need, like the standard library.<br>
<br>
The eclib library requires the compiler to support the c++11 standard.please read the source code before using.<br>

Partial file list:<br>

 file          |   description   
 --------------|----------------------------| 
 c11_memory.h  | memory pool for map,vector 
 c11_hash.h    | hash algorithm 
 c11_map.h     | hash map  
 c11_vecotr.h  | vector  collection 
 c11_array.h   | Array in the stack 
 c11_fifo.h   | FIFO collection 
 c11_stack.h  | stack collection 
 c11_json.h   | parse json object 
 c_protobuf.h | encode/decode for google Protocol Buffers 
 c11_event.h  | event notify for thread 
 c11_mutex.h  | mutex and spinlock 
 c11_thread.h | thread class 
 c11_config.h | read INI file, csv file 
 c11_log.h    | log class 
 c11_daemon.h | daemon frame for linux 
 c11_tls12.h  | TLS1.2 sessions 
 c11_websocket.h | websocket server 
 c11_netio.h  | net IO toolkits 
 c11_xpoll.h  | Asynchronous network IO class 
 c11_tcp.h    | TCP server and client 
 c11_tcptls.h | TLS 1.2 for TCP server and client 
 c11_httpws.h | websocket on HTTP 
 c11_httpswss.h | websocket on HTTPS 
 c_odbc.h     | wrapper class for windows ODBC 
 c_file.h     | file class 
 c11_handle.h | Dynamic library Handle class 
 c_diskio.h   | disk IO toolkits 
 c_str.h      | string toolkits 
 c_md5.h      | fast MD5 encode/decode 
 c_base64.h   | fast base64 encode/decode 
 c_sha1.h     | fast SHA1 encode/decode 
 c_guid.h     | GUID maker 
 c_xstorage.h | Composite file storage 
 c_udp.h      | UDP server 
