# Author: Meuz Kidane
# Date: Feb, 2024

# Importing Modules

import socket
import dpkt
import pygeoip

GEOLITE_DB  = "GeoLiteCity.dat"
TRAFFIC     = "traffic.pcap"

# Convert IP to geo and generate KML
def retkml(dst, src):
    dst_record = geo_ip.record_by_name(dst)
    src_record = geo_ip.record_by_name("154.20.72.95")

    # print(f"debug: {type(dst_record)}")

    # Ignore NoneType for Private IPv4
    if (dst_record != None ):

        try:
            dst_long, dst_lat = dst_record["longitude"], dst_record["latitude"]
            src_long, src_lat = src_record["longitude"], src_record["latitude"]

            kml = f"{dst_long},{dst_lat} \n {src_long},{src_lat} "
            
            # print (dst_long, dst_lat)
            return kml
            # return dst_long, dst_lat
        except e:
            print(f"Error: {e}")
            return ""
    else:
        return ""


# Read packets from pcap file and generate KML
def plot_ips(pcap):
    plt = ""
    for ts, buff in pcap:
        eth = dpkt.ethernet.Ethernet(buff)
        ip = eth.data
        # Check if the IP packet is IPv4
        if isinstance(ip, dpkt.ip.IP):
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            kml = retkml(dst, src)

            # print (f"debug: {kml}, {dst}, {src}")
            plt += str(kml)
    return plt


# Init the Geolocaion Database
geo_ip = pygeoip.GeoIP(GEOLITE_DB)

def main():
    # Open the wireshark file to read in a binary format
    file = open(TRAFFIC ,"rb")
    
    # Read packets from the .pcap file
    pcap = dpkt.pcap.Reader(file)

    # Define style for KML
    kml_template = f"""
    <?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Style id="yellowLineGreenPoly">
        <LineStyle>
          <color>7f00ffff</color>
          <width>1.7</width>
        </LineStyle>
        <PolyStyle>
          <color>7f00ff00</color>
        </PolyStyle>
      </Style>
    <Placemark>
        <LineString>
          <coordinates>
            {plot_ips(pcap)}
          </coordinates>
        </LineString>
      </Placemark>
    </kml>
    """

    print(kml_template)


if __name__ == "__main__":
    main()
