import multiprocessing
from external import ftp_sniffer, packetSniff, ssh_sniffer, tcp_sniffer, http_sniffer
from layers import layer1_process, layer2_process, layer3_process



sniffer_ftp = multiprocessing.Process(target=ftp_sniffer)
sniffer_ssh = multiprocessing.Process(target=ssh_sniffer)
sniffer_tcp = multiprocessing.Process(target=tcp_sniffer)
sniffer_http = multiprocessing.Process(target=http_sniffer)
layer1 = multiprocessing.Process(target=layer1_process)
layer2 = multiprocessing.Process(target=layer2_process)
layer3 = multiprocessing.Process(target=layer3_process)
packsniff = multiprocessing.Process(target = packetSniff)

started = None

def layers_inspection():
    global started
    if started:
        # sniffer_tcp.join()
        # sniffer_ftp.join()
        # sniffer_ssh.join()
        # sniffer_http.join()
        packsniff.join()
        layer1.join()
        # layer2.join()
        layer3.join()
    elif not started:
        started = True
        # sniffer_tcp.start()
        # sniffer_ftp.start()
        # sniffer_ssh.start()
        # sniffer_http.start(
        packsniff.start()
        layer1.start()
        # layer2.start()
        layer3.start()
        # sniffer_tcp.join()
        # sniffer_ftp.join()
        # sniffer_ssh.join()
        # sniffer_http.join()
        packsniff.join()
        layer1.join()
        # layer2.join()
        layer3.join()


def layers_inspection_1():
    global started
    if started:
        sniffer_tcp.join()
        sniffer_ftp.join()
        sniffer_ssh.join()
        sniffer_http.join()
 
    elif not started:
        started = True
        sniffer_tcp.start()
        sniffer_ftp.start()
        sniffer_ssh.start()
        sniffer_http.start()
        sniffer_tcp.join()
        sniffer_ftp.join()
        sniffer_ssh.join()
        sniffer_http.join()


if __name__ == '__main__':
    layers_inspection()
