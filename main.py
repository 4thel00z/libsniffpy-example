from sniff import get_socket, type_predicate, subtype_predicate
from sys import stderr
from dpkt import ieee80211
from dpkt.radiotap import Radiotap


def loop(iface: str):
    s = get_socket(iface)
    try:
        while True:
            try:
                yield Radiotap(s.recv(2034))
            except Exception as err:
                print("[*] Could not decode a packet", err, file=stderr)
    except KeyboardInterrupt:
        print("[*] Closed the loop, through SIGINT")


if __name__ == "__main__":
    mgmt_predicate = type_predicate(ieee80211.MGMT_TYPE)
    probe_request_predicate = subtype_predicate(ieee80211.M_PROBE_REQ)

    mgmt_packets = filter(mgmt_predicate, loop("wlan0mon"))
    probe_requests = filter(probe_request_predicate, mgmt_packets)
    
    for pkg in probe_requests:
        print(pkg)
