from flask import Flask, render_template, request, redirect, url_for, session, flash
import socket
import threading

app = Flask(__name__)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/portfolio')
def portfolio():
    return render_template("portfolio.html")


@app.route('/project')
def project():
    return render_template("project.html")


@app.route('/portscan', methods=['POST'])
def portscan():
    open_ports = []
    closed_ports = []
    ports_info = {}
    combine_port = {}
    tcp_ports = {}
    udp_ports = {}
    
    url = request.form['url']
    for char in ["http://", "https://", "/"]:
        url = url.replace(char, "")
    host = socket.gethostbyname(url)
    
    start_port = request.form['start']
    end_port = request.form['end']
    single_port = request.form['single_port']
    
    def tcp_udp(port):
        # Cek TCP
        try:
            socket.getservbyport(port, "tcp")
            tcp_ports[port] = "tcp".upper()
        except OSError:
            pass
        # Cek UDP
        try:
            socket.getservbyport(port, "udp")
            udp_ports[port] = "udp".upper()
        except OSError:
            pass
        # Cek Combine
        if port in tcp_ports and port in udp_ports:
            combine_port[port] = 'tcp/udp'.upper()
        elif port in tcp_ports:
            combine_port[port] = tcp_ports[port]
        elif port in udp_ports:
            combine_port[port] = udp_ports[port]
        else:
            combine_port[port] = 'unknown'
    
    def name_port(port):
        try:
            service = socket.getservbyport(port)
            ports_info[port] = service.upper()
        except:
            ports_info[port] = "unknown"
    
    def scan_single(host, port):
        host = socket.gethostbyname(host)
        tcp_udp(port), name_port(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
    
    def range_scan(host, start_port, end_port):
        threads = []
        for port in range(start_port, end_port+1):
            t = threading.Thread(target=scan_single, args=(host, port))
            threads.append(t)
        for x in threads:
            x.start()
        for x in threads:
            x.join()
    
    if start_port.isdigit() and end_port.isdigit() and (not single_port):
        range_scan(host, int(start_port), int(end_port))
    elif single_port.isdigit() and (not start_port) and (not end_port):
        scan_single(host, int(single_port))
    
    open_ports.sort()
    closed_ports.sort()
    return render_template("project.html", open=open_ports, closed=closed_ports, info=ports_info, url=url, start=start_port, end=end_port, single_port=single_port, host=host, tcp=tcp_ports, udp=udp_ports, combine=combine_port)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
    # app.run(debug=True)
