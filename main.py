# Author: Meuz Kidane
# Date: Feb, 2024

# Importing Modules

import socket
import dpkt
import pygeoip
from requests import get
import sys

# Const 
GEOLITE_DB  = "GeoLiteCity.dat"
TRAFFIC     = "traffic.pcap"

# Init the Geolocaion_IP Database
GEODB = pygeoip.GeoIP(GEOLITE_DB)

def check_private_ip(ip:str):
    """
    Check IP address for private or public
    
    This funtion takes an ip address and check if it is either a public or private address
    and return True if the address is private
    """
    # Split ip in to 4 octats
    _ip = ip.split(".")

    if _ip[0] == "192" or _ip[0] == "10":
        return True
    elif _ip[0] == "172":
        if int(_ip[1]) >= 16 and int(_ip[1]) <= 31:
            return True
        else:
            return False
    else:
        return False

def get_public_ip():
    """
      Resolve device's public address
      
      This will query ipify to get the public ip address of the device
      
      Parameters:
        None
        
      Return;
        public_ip (str): The publuic IP address
    """
    
    public_ip = get('https://api.ipify.org').content.decode('utf8')
    
    return public_ip

def get_ips(pcap, public_ip):
    """
      Retrieve IP addresses from a packet source.

      This function fetches a list of IP addresses from a specified data source
      and returns them as a list.

      Parameters:
          pcap (): The network data source with all the packets

      Returns:
          ip_pairs (list[(set)]): A list of IP addresses.
    """
    ip_pairs = []

    for _, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        addr = eth.data

        # Check if the ip addresses are IPV4
        if (isinstance(addr, dpkt.ip.IP)):
            src = socket.inet_ntoa(addr.src)
            dst = socket.inet_ntoa(addr.dst)

            # TODO: check for private ip add of the src and des
            if check_private_ip(src): src = public_ip
            if check_private_ip(dst): dst = public_ip
            
            # ? If ip is private discard them or replace with device external ip
            # Replacing with device ip makes sence since its internal traffic

            ip_pairs.append((src, dst))

    return ip_pairs
  
  
def get_loc(ip_pairs):
    """
    Retrieve locations corresponding to IP addresses.

    This function retrieves the geographical locations corresponding to the
    provided IP addresses and returns them as a string.

    Parameters:
        ip_pairs (list): List of IP address pairs.

    Returns:
        loc_pairs (str): A string containing geographical locations.
    """
    loc_pairs = ""

    for ip in ip_pairs:
        src_record = GEODB.record_by_name(ip[0])
        dst_record = GEODB.record_by_name(ip[1])

        try:
            src_long, src_lat = src_record["longitude"], src_record["latitude"]
            dst_long, dst_lat = dst_record["longitude"], dst_record["latitude"]
            loc_pairs += f"{dst_long}, {dst_lat}\n{src_long}, {src_lat}\n"
        except Exception as e:
            # TODO: write the following error to .log
            # sys.stderr.write(f"ERROR: Unable to retrieve location for IP {ip[1]} - {e}")
            pass

    return loc_pairs.strip()
  

def generate_co(loc_pairs):
    """
    Generate a Coordinate for the KML file for each IP address.

    This function generates a KML file containing placemarks for each IP
    address location.

    Parameters:
        loc_pairs (str): String containing geographical locations.

    Returns:
        kml_template (str): Generated KML template.
    """
    kml_template = f"""
    <?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Document>
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
              {loc_pairs}
            </coordinates>
          </LineString>
        </Placemark>
      </Document>
    </kml>
    """

    return kml_template

def map_ntk(kml_template):
    """
      Map network traffic to geographical locations.

      This function maps network traffic to geographical locations and generates
      a visualization of the traffic on a world map.

      Parameters:
          kml_template (str)

      Returns:
          None
    """
    pass

def main():
    """
      Main function for network visualization.

      This function loads network data from a file, Generate a KML File, and constructs a network graph,
      and visualizes the graph using a specified layout algorithm.

    """

    # Open the wireshark .pcap file to read in a binary format
    file = open(TRAFFIC ,"rb")
    
    # Read packets from the .pcap file
    pcap = dpkt.pcap.Reader(file)
    
    # Get device public ip
    public_ip = get_public_ip()

    ip_pairs      = get_ips(pcap, public_ip)
    loc_pairs     = get_loc(ip_pairs)
    kml_template  = generate_co(loc_pairs)
    map_ntk(kml_template)
    
    # TODO:
    # Command-line argument -o (write kml file to file), -i (interactive map)

    print(kml_template)


if __name__ == "__main__":
    main()
