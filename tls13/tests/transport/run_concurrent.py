#!/usr/bin/env python3
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from run_loopback import certificates

with tempfile.TemporaryDirectory(prefix='tls-fixer-concurrent-') as temporary:
    directory=Path(temporary)
    certificates(directory)
    for version in (ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=context.maximum_version=version
        context.load_cert_chain(directory/'server.pem',directory/'server.key')
        listener=socket.socket()
        listener.bind(('127.0.0.1',0)); listener.listen(128); listener.settimeout(12)
        errors=[]
        def serve():
            clients=[]
            try:
                for _ in range(64):
                    raw,_=listener.accept(); raw.settimeout(12)
                    clients.append(context.wrap_socket(raw,server_side=True))
                for connection in clients:
                    connection.sendall(b'x')
            except Exception as error:
                errors.append(repr(error))
            finally:
                for connection in clients: connection.close()
                listener.close()
        worker=threading.Thread(target=serve,daemon=True); worker.start()
        result=subprocess.run([sys.argv[1],str(directory/'ca.pem'),str(listener.getsockname()[1])],
                              text=True,capture_output=True,timeout=45)
        worker.join(15)
        assert result.returncode==0,(result.returncode,result.stdout,result.stderr,errors)
        assert not worker.is_alive() and not errors,errors
        print(version.name+': '+result.stdout.strip(),flush=True)
