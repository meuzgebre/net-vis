# Author: Meuz Kidane
# Date: Feb, 2024

# Importing Modules

import socket
import dpkt
import pygeoip

GEOLITE_DB  = "GeoLiteCity.dat"
TRAFFIC     = "traffic.pcap"

# Convert IP to geo
def retkml(dst, src):
    dst = geo_ip.record_by_name(dst)
    src = geo_ip.record_by_name(src)
    
    try:
        dst_long = dst["longitude"]
        dst_lat = dst["latitude"]
        
        src_long = src["longitude"]
        src_lat = src["latitude"]
        
        
        kml = (
            f"""
            <Placemark>
            <name>%s</name>
            <extrude>1</extrude>
            <styleUrlUrl>#My Site</styleUrl>
            <LineString>
            <coordinate>%6f,%6f\n%6f,%6f</coordinate>
            </LineString>
            </Placemark>
            """
        )%(dst, dst_long, dst_lat, src, src_long, src_lat)
        
        print(kml)
        return kml
    except:
        pass
  
 
def plot_ips(pcap):
    plt = ""
    for (ts, buff) in pcap:
        eth = dpkt.ethernet.Ethernet(buff)
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        
        kml = retkml(dst, src)
        
        # plt += kml
        # print(dst, src)
        
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
    {plot_ips(pcap)}
    </Document>
    </kml>
    """

    print(kml_template)


if __name__ == "__main__":
    main()
