import socket
import ssl
import sys

def check_tls_version(hostname, port):
    """Test a specific TLS version"""
    print(f"\nTesting TLS support for {hostname}:{port}")
    
    # Create standard context
    print("Using standard context to verify what's actually working:")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                print(f"Connected using: {version}")
                print(f"Cipher: {cipher}")
    except Exception as e:
        print(f"Standard connection error: {str(e)}")
    
    # Test TLS 1.2
    print("\nTLS 1.2 Test:")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Success! Connected with: {ssock.version()}")
                print(f"Cipher: {ssock.cipher()}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # Test TLS 1.3
    print("\nTLS 1.3 Test:")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Success! Connected with: {ssock.version()}")
                print(f"Cipher: {ssock.cipher()}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # Test TLS 1.1
    print("\nTLS 1.1 Test:")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Success! Connected with: {ssock.version()}")
                print(f"Cipher: {ssock.cipher()}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # Test TLS 1.0
    print("\nTLS 1.0 Test:")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Success! Connected with: {ssock.version()}")
                print(f"Cipher: {ssock.cipher()}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        hostname = sys.argv[1]
    else:
        hostname = "changedetection.io"
    
    port = 443
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    check_tls_version(hostname, port)