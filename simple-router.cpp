/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"
#include <fstream>

namespace simple_router {

static Buffer broadcast_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  // print_hdr_eth(packet.data());
  // std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  struct ethernet_hdr ether_hdr;
  getEthernetHeader(packet, ether_hdr);


  /**when destination hard-ware address is neither the corresponding MAC address of the interface nor a broadcast
   *  address( FF:FF:FF:FF:FF:FF )**/
  std::vector<unsigned char> tmp_dest(ether_hdr.ether_dhost, ether_hdr.ether_dhost + 6);
  if(findIfaceByMac(tmp_dest) == nullptr && !(tmp_dest  == broadcast_addr))  {
    std::cerr << "Ethernet frames not destined to the router, ignoring" << std::endl;
    return;
  }

  if(ether_hdr.ether_type == ntohs(0x0800)) {
    handleIPv4Packet(packet, inIface, ether_hdr);
  }

  if(ether_hdr.ether_type == ntohs(0x0806)) {
    handleArpPacket(packet, inIface, ether_hdr);
  }
}


void
SimpleRouter::handleIPv4Packet(const Buffer& packet, const std::string& Iface, struct ethernet_hdr& ether_hdr ){
  Buffer disp_packet = packet;

  struct ip_hdr ipv4_hdr;
  getIPv4Header(packet, ipv4_hdr);

  std::cerr << "begin:" << std::endl;
  print_hdr_eth(packet.data());
  uint8_t tmp_ip_hdr[20];
  memcpy(tmp_ip_hdr, &packet[14], sizeof(tmp_ip_hdr));
  print_hdr_ip(tmp_ip_hdr);
  // print_addr_ip_int(htonl(ipv4_hdr.ip_src));
  // print_addr_ip_int(htonl(ipv4_hdr.ip_dst));
  
  uint16_t ip_sum = ipv4_hdr.ip_sum;
  ipv4_hdr.ip_sum = 0x0000;
  uint16_t ck_sum = cksum(&ipv4_hdr, sizeof(ipv4_hdr));
  if(ck_sum != ip_sum){
    std::cerr << ck_sum << std::endl;
    std::cerr << ip_sum << std::endl;
    std::cerr << "invalid ip_sum";
    return;
  }
  // struct icmp_t3_hdr i_t3_hdr;
  // getIcmpt3Header(packet, i_t3_hdr);
  // if(i_t3_hdr.icmp_type == 0x0B || i_t3_hdr.icmp_type == 0x08 || i_t3_hdr.icmp_type == 0x03){
  //   // be an icmp packet
  //   //TODO: checksum
  //   if(i_t3_hdr.icmp_type == 0x0B){
      
  //   }
    
  //   //???
  //   handleIcmpPacket(0x08, packet, disp_packet);
  // }

  /**update ttl and cksum**/ 

  const Interface *dstIface = findIfaceByIp(ipv4_hdr.ip_dst);
  if(dstIface != nullptr){
    /**
     * destined to a router -- be an ICMP echo packet
     * */
    // if(ipv4_hdr.ip_ttl < 0){
    //   //TODO: send an ICMP packet of time exceeded 
    //   sendIcmpt3Packet(0x0B, packet, Iface);
    //   return;
    // }
    if(ipv4_hdr.ip_p == 0x06 || ipv4_hdr.ip_p == 0x11){
    // send an Port Unreachable message
    std::cerr << "**************masaka type == 3??" << std::endl;
    sendIcmpt3Packet(0x03, 0x03, packet, Iface);
    }

    struct icmp_hdr i_hdr;
    getIcmpHeader(packet, i_hdr);
    
   //TODO: to correct
    uint16_t cur_cksum = i_hdr.icmp_sum;
    uint16_t tmp_cksum = 0x0000;

     std::cerr << "ip len: " << ipv4_hdr.ip_len << std::endl;

    const uint16_t icmp_size = ntohs(ipv4_hdr.ip_len) - 20;

    std::cerr << "size" << icmp_size << std::endl;

    uint8_t* tmp_icmp_hdr = new uint8_t[icmp_size];
    memcpy(tmp_icmp_hdr, &packet[34], icmp_size);
    memcpy(tmp_icmp_hdr + 2, &tmp_cksum, 2);
    uint16_t icmp_cksum = cksum(tmp_icmp_hdr, icmp_size);
    if(icmp_cksum != cur_cksum){
      std::cerr << "invalid icmp_sum" << std::endl;
      std::cerr << icmp_cksum << std::endl;
      std::cerr << cur_cksum << std::endl;
      return;
    }
    if(i_hdr.icmp_type == 0x08){
      uint8_t tmp_type = 0x00;
      memcpy(tmp_icmp_hdr, &tmp_type, 1);
      icmp_cksum = cksum(tmp_icmp_hdr, icmp_size);
      
      i_hdr.icmp_type = 0x00;
      i_hdr.icmp_sum = icmp_cksum;
      memcpy(&disp_packet[34], &i_hdr, sizeof(i_hdr));
      invertPacket(ether_hdr, ipv4_hdr);
      //TODO: cksum
      ipv4_hdr.ip_ttl = 0xff;
      ipv4_hdr.ip_sum = ntohs(0x0000);
      ipv4_hdr.ip_sum = cksum(&ipv4_hdr, sizeof(ipv4_hdr));
      loadIPv4Packet(disp_packet, ether_hdr, ipv4_hdr);
      std::cerr<< "echo reply:" << std::endl;
      print_hdrs_k(disp_packet);
      sendPacket(disp_packet, Iface);
    }
  }
  else{
    /**
     * be a forwarding packet
     * */
    // TODO: Try
    std::cerr << "be a forwaiding packet" << std::endl;

    uint8_t ttl = ipv4_hdr.ip_ttl - 1;
    if(ttl < 1){
      //TODO: send an ICMP packet of time exceeded 
      sendIcmpt3Packet(0x0B, 0x00, packet, Iface);
      return;
    }

    ipv4_hdr.ip_ttl = ttl;

    struct icmp_hdr i_hdr;
    getIcmpHeader(packet, i_hdr);
    RoutingTableEntry rt_entry;
    try{
       rt_entry = m_routingTable.lookup(ipv4_hdr.ip_dst);
       std::cerr<<"ip.dst:"<<std::endl;
      //  print_addr_ip_int(ipv4_hdr.ip_dst);
    }catch(std::runtime_error){
      std::cerr << "routingtable entry look up failed" << std::endl;
      return;
    }

    std::cerr << "rt_entry.dest:" << std::endl;
    // print_addr_ip_int(htonl(rt_entry.dest));
    const Interface *outIface =  findIfaceByName(rt_entry.ifName);
      
    /**update address for ethernet header address**/

    // TODO: maybe not correct
   
    std::shared_ptr<ArpEntry> arp_entry =  m_arp.lookup(ipv4_hdr.ip_dst);
    if(arp_entry == nullptr){
      /**
       * valid entry is not found
       * queue the received packet and start 
       * ?sending ARP request 
       * to discover the IP-MAC mapping.
       * */
      /**broadcast ARP packet to get hardware addressque**/
      std::cerr << "no valid arp_entry" << std::endl;
      // ipv4_hdr.ip_sum = ntohs(0x0000);
      // ipv4_hdr.ip_sum = cksum(&ipv4_hdr, sizeof(ipv4_hdr));
      // loadIPv4Packet(disp_packet, ether_hdr, ipv4_hdr);

      // print_hdr_eth(disp_packet.data());
      // uint8_t tmp_ip_hdr[20];
      // memcpy(tmp_ip_hdr, &disp_packet[14], sizeof(tmp_ip_hdr));
      // print_hdr_ip(tmp_ip_hdr);

      m_arp.queueRequest(ipv4_hdr.ip_dst, disp_packet, rt_entry.ifName);
      return;
    }
    else{
      /**valid entry found
       * dispatch ipv4 packet to the next-hop address**/
      std::cerr << "###################valid entry found#############" << std::endl;
      memcpy(ether_hdr.ether_shost, (outIface->addr).data(), sizeof(ether_hdr.ether_shost));
      memcpy(ether_hdr.ether_dhost, &(arp_entry->mac[0]), sizeof(ether_hdr.ether_dhost));
    /**update ethernet frame with ether_hdr and ipv4_hdr**/
      loadIPv4Packet(disp_packet, ether_hdr, ipv4_hdr);
      std::cerr << "transmit the packet"<< std::endl;
      print_hdrs_k(disp_packet);
      sendPacket(disp_packet, rt_entry.ifName);
    }
  }
}

void
SimpleRouter::handleArpPacket(const Buffer& packet, const std::string& inIface, struct ethernet_hdr& ether_hdr){
  struct arp_hdr a_hdr;
  getArpHeader(packet, a_hdr);
  Buffer disp_packet = packet;

  if(a_hdr.arp_op == ntohs(0x0001)){
    //Arp request packet
    const Interface *inIf = findIfaceByName(inIface);
    if(inIf->ip != a_hdr.arp_tip){
      /**ignore other ARP requests not responding to ip of Interface**/
      return;
    }
    /**
     * update ethernet frame and send it
     * update arp header
     * */
    a_hdr.arp_op = ntohs(0x0002);
    memcpy(&a_hdr.arp_tip, &a_hdr.arp_sip, sizeof(a_hdr.arp_tip));
    memcpy(a_hdr.arp_tha, a_hdr.arp_sha, sizeof(a_hdr.arp_tha));
    memcpy(&a_hdr.arp_sip, &inIf->ip, sizeof(a_hdr.arp_sip));
    memcpy(a_hdr.arp_sha, (inIf->addr).data(), sizeof(a_hdr.arp_sha));

    memcpy(ether_hdr.ether_dhost, ether_hdr.ether_shost, sizeof(ether_hdr.ether_dhost));
    memcpy(ether_hdr.ether_shost, (inIf->addr).data(), sizeof(ether_hdr.ether_shost));

    memcpy(&disp_packet[0], &ether_hdr, sizeof(ether_hdr));
    memcpy(&disp_packet[14], &a_hdr, sizeof(a_hdr));
    
    sendPacket(disp_packet, inIface);
  }
  else if(a_hdr.arp_op == ntohs(0x0002)){
    //Arp reply packet

    std::cerr << "receive an arp reply;" << std::endl;
    uint8_t* tmp_data = (uint8_t*)packet.data();
    print_hdr_arp(tmp_data + 14);
    std::cerr << "3" << std::endl;
    Buffer reply_mac = std::vector<unsigned char>(6, 0);
    std::cerr << "1" << std::endl;
    memcpy(&reply_mac[0], a_hdr.arp_sha, sizeof(reply_mac));
    std::cerr << "2" << std::endl;
    //TODO: check why it sames that the arpentry is not inserted into the arpcache;
    //possible method: print arp_sip and pendingpackets[0].ip check if equal.
    std::cerr << "arp.sip:" << std::endl;
    print_addr_ip_int(a_hdr.arp_sip);
    std::shared_ptr<ArpRequest> arp_req = m_arp.insertArpEntry(reply_mac, a_hdr.arp_sip);
    if(arp_req == nullptr){
       return;
    }
    std::cerr << "4" << std::endl;
    m_arp.sendPendingPackets(arp_req);
    std::cerr << "5" << std::endl;
    m_arp.removeRequest(arp_req);
    std::cerr << "6" << std::endl;
  }
}


// void
// SimpleRouter::handleIcmpPacket(uint16_t type, const Buffer& packet, Buffer& disp_packet)
// {
//   if(type == 0x08){
//     struct icmp_hdr i_hdr;
//     getIcmpHeader(packet, i_hdr);
//     i_hdr.icmp_type = 0x01; 
//     memcpy(&disp_packet[34], &i_hdr, sizeof(i_hdr));  
//   }
//   if(type == 0x0B || type == 0x03){
//     struct ethernet_hdr ether_hdr;
//     getEthernetHeader(packet, ether_hdr);
//     struct ip_hdr ipv4_hdr;
//     getIPv4Header(packet, ipv4_hdr);
//     invertPacket(ether_hdr, ipv4_hdr);
//     ipv4_hdr.ip_ttl = 0xff;
//     ipv4_hdr.ip_sum = ntohs(0x0000);
//     ipv4_hdr.ip_sum = cksum(&ipv4_hdr, sizeof(ipv4_hdr));
//     struct icmp_hdr i_hdr;
//     createIcmpHeader(packet, type, i_hdr);
//     loadIcmpPacket(disp_packet, ether_hdr, ipv4_hdr, i_hdr);
//   }
// }

void 
SimpleRouter::sendIcmpt3Packet(uint8_t type, uint8_t code, const Buffer& packet, const std::string& Iface){
  //? if the size 50 is correct
  std::cerr << "#############sendIcmpt3Packet#############" << std::endl;
  Buffer disp_packet = std::vector<unsigned char>(70, 0);

  const Interface* outIface = findIfaceByName(Iface);

  struct ethernet_hdr ether_hdr;
  getEthernetHeader(packet, ether_hdr);
  struct ip_hdr ipv4_hdr;
  getIPv4Header(packet, ipv4_hdr);
  invertPacket(ether_hdr, ipv4_hdr);
  ipv4_hdr.ip_src = outIface->ip;
  ipv4_hdr.ip_ttl = 0xff;
  ipv4_hdr.ip_len = htons(0x0038);
  ipv4_hdr.ip_p = 0x01;
  ipv4_hdr.ip_sum = ntohs(0x0000);
  ipv4_hdr.ip_sum = cksum(&ipv4_hdr, sizeof(ipv4_hdr));
    
  struct icmp_t3_hdr i_t3_hdr;
  memset(&i_t3_hdr, 0x00, sizeof(i_t3_hdr));
  createIcmpt3Header(packet, type, code, i_t3_hdr);
    
  loadIcmpt3Packet(disp_packet, ether_hdr, ipv4_hdr, i_t3_hdr);

  print_hdrs_k(disp_packet);
  sendPacket(disp_packet, Iface);
}


// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}


void
SimpleRouter::createArpRequestPacket(uint32_t dst_ip, const std::string& Iface, Buffer& arp_packet){
      /**create arp header**/
      const  Interface* outIface = findIfaceByName(Iface);
      struct arp_hdr a_hdr;
      struct ethernet_hdr ether_hdr;

      unsigned short hrd = ntohs(0x0001);
      unsigned short pro = ntohs(0x0800);
      unsigned short op = ntohs(0x0001);

      uint16_t arp_type = ntohs(0x0806);

      //? is it correct?
      a_hdr.arp_hln = 6;
      a_hdr.arp_pln = 4;
      memcpy(&a_hdr.arp_hrd, &hrd, sizeof(a_hdr.arp_hrd));
      memcpy(&a_hdr.arp_pro, &pro, sizeof(a_hdr.arp_pro));
      memcpy(&a_hdr.arp_op, &op, sizeof(a_hdr.arp_op));
      memcpy(&a_hdr.arp_hrd, &hrd, sizeof(a_hdr.arp_hrd));
      memcpy(&a_hdr.arp_sip, &outIface->ip, sizeof(a_hdr.arp_sip));
      memcpy(a_hdr.arp_sha, &(outIface->addr[0]), sizeof(a_hdr.arp_sha));
      memcpy(&a_hdr.arp_tip, &dst_ip, sizeof(a_hdr.arp_tip));
      memcpy(a_hdr.arp_tha, &(broadcast_addr[0]), sizeof(a_hdr.arp_tha));
      
      /**create an arp_packet to broadcast**/
      memcpy(ether_hdr.ether_shost, &(outIface->addr[0]), sizeof(ether_hdr.ether_shost));
      memcpy(ether_hdr.ether_dhost, &(broadcast_addr[0]), sizeof(ether_hdr.ether_dhost));
      memcpy(&ether_hdr.ether_type, &arp_type, sizeof(ether_hdr.ether_type));
      memcpy(&arp_packet[0], &ether_hdr, sizeof(ether_hdr));
      memcpy(&arp_packet[14], &a_hdr, sizeof(a_hdr));
}


void
SimpleRouter::createIcmpt3Header(const Buffer& packet, uint8_t type, uint8_t code, struct icmp_t3_hdr& i_t3_hdr){
  //? if the pointere is needed?
  i_t3_hdr.icmp_type = type;
  i_t3_hdr.icmp_code = code;
  memcpy(i_t3_hdr.data, &packet[14], sizeof(i_t3_hdr.data));
  i_t3_hdr.icmp_sum = 0x0000;
  i_t3_hdr.icmp_sum = cksum(&i_t3_hdr, sizeof(i_t3_hdr));
}


  

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::getEthernetHeader(const Buffer& packet, struct ethernet_hdr& eth_hdr)
{
  memcpy(&eth_hdr, &packet[0], sizeof(eth_hdr));
}

void
SimpleRouter::getIPv4Header(const Buffer& packet, struct ip_hdr& ipv4_hdr)
{
  memcpy(&ipv4_hdr, &packet[14], sizeof(ipv4_hdr));
}

void
SimpleRouter::getArpHeader(const Buffer& packet, struct arp_hdr& a_hdr)
{
  memcpy(&a_hdr, &packet[14], sizeof(a_hdr));
}

void
SimpleRouter::getIcmpHeader(const Buffer& packet, struct icmp_hdr& i_hdr)
{
  memcpy(&i_hdr, &packet[34], sizeof(i_hdr));
}

void 
SimpleRouter::getIcmpt3Header(const Buffer& packet, struct icmp_t3_hdr& i_t3_hdr)
{
  memcpy(&i_t3_hdr, &packet[34], sizeof(i_t3_hdr));
}


void
SimpleRouter::loadIPv4Packet(Buffer& packet, struct ethernet_hdr& eth_hdr, struct ip_hdr& ipv4_hdr){
  memcpy(&packet[0], &eth_hdr, sizeof(eth_hdr));
  memcpy(&packet[14], &ipv4_hdr, sizeof(ipv4_hdr));
}

void
SimpleRouter::loadIcmpt3Packet(Buffer& packet, struct ethernet_hdr& eth_hdr, struct ip_hdr& ipv4_hdr, 
struct icmp_t3_hdr& i_t3_hdr)
{
  loadIPv4Packet(packet, eth_hdr, ipv4_hdr);
  memcpy(&packet[34], &i_t3_hdr, sizeof(i_t3_hdr));
}


void
SimpleRouter::invertPacket(struct ethernet_hdr& ether_hdr, struct ip_hdr& ipv4_hdr){
  uint16_t tmp_buffer[6]; 
  memcpy(tmp_buffer, ether_hdr.ether_shost, sizeof(ether_hdr.ether_shost)); 
  memcpy(ether_hdr.ether_shost, ether_hdr.ether_dhost, sizeof(ether_hdr.ether_dhost));
  memcpy(ether_hdr.ether_dhost, tmp_buffer, sizeof(ether_hdr.ether_dhost));  

  uint32_t tmp_ip;
  memcpy(&tmp_ip, &ipv4_hdr.ip_src, sizeof(ipv4_hdr.ip_src));
  memcpy(&ipv4_hdr.ip_src, &ipv4_hdr.ip_dst, sizeof(ipv4_hdr.ip_src));
  memcpy(&ipv4_hdr.ip_dst, &tmp_ip, sizeof(ipv4_hdr.ip_dst));
}


void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
