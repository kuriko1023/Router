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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {


// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  std::lock_guard<std::recursive_mutex> lock(m_mutex);

  std::cerr << *this << std::endl;

  for(auto it = m_arpRequests.begin(); it != m_arpRequests.end(); it++) {
    std::shared_ptr<ArpRequest> req = *it;
    handleRequest(req);
  }
  
  for(auto it = m_cacheEntries.begin(); it != m_cacheEntries.end();) {
    if((*it)->isValid == false){
      it = m_cacheEntries.erase(it);
    }
    else{
      ++it;
    }
  }

  // std::cerr<< "##############floop end" << std::endl;

}

void
ArpCache::handleRequest(const std::shared_ptr<ArpRequest> req){
   std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if(req->nTimesSent < 5){
    const std::string outIface = ((req->packets).front()).iface;
    Buffer arp_request = std::vector<unsigned char>(42, 0);
    m_router.createArpRequestPacket(req->ip, outIface, arp_request);
    print_hdr_eth(arp_request.data());
    uint8_t tmp_arp_hdr[28];
    memcpy(tmp_arp_hdr, &arp_request[14], sizeof(tmp_arp_hdr));
    print_hdr_arp(tmp_arp_hdr);
    m_router.sendPacket(arp_request, outIface);
    req -> nTimesSent += 1;
    req -> timeSent = std::chrono::steady_clock::now();   //? ******is it correct?
  }
  else if(req->nTimesSent >= 5){
    for(auto it = req->packets.begin(); it != req->packets.end(); it++){
      PendingPacket p_packet = *it;
      struct ip_hdr ipv4_hdr;
      m_router.getIPv4Header((*it).packet, ipv4_hdr);
      const RoutingTable rt = m_router.getRoutingTable();
      RoutingTableEntry rt_entry = rt.lookup(ipv4_hdr.ip_src);
      m_router.sendIcmpt3Packet(0x03, 0x01, (*it).packet, rt_entry.ifName);
    }
  }
}

void 
ArpCache::sendPendingPackets(const std::shared_ptr<ArpRequest> arp_req){

  std::lock_guard<std::recursive_mutex> lock(m_mutex);

  for(auto it = arp_req->packets.begin(); it != arp_req->packets.end(); it++){
    std::cerr << "2-1" << std::endl;
    PendingPacket p_packet = *it;
   
    /**fill the ethernet_hdr.dhost with mac address(look up in arp cache)**/
    struct ethernet_hdr ether_hdr;
    memcpy(&ether_hdr, &(p_packet.packet[0]), sizeof(ether_hdr));
    std::shared_ptr<ArpEntry> arp_entry = lookup(arp_req->ip);
    // if(arp_entry == nullptr){
    //   std::cerr << "nullptr" << std::endl;
    // }

    const Interface* outIface = m_router.findIfaceByName(p_packet.iface);
    memcpy(ether_hdr.ether_shost, (outIface->addr).data(), sizeof(ether_hdr.ether_shost));
    memcpy(ether_hdr.ether_dhost, &(arp_entry->mac[0]), sizeof(ether_hdr.ether_dhost));
    std::cerr << "2-4" << std::endl;
    memcpy(&p_packet.packet[0], &ether_hdr, sizeof(ether_hdr));
    std::cerr << "#########send pending packet:" << std::endl;
    print_hdrs_k(p_packet.packet);
    m_router.sendPacket(p_packet.packet, p_packet.iface);
  }
}

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::recursive_mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface){

  std::lock_guard<std::recursive_mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  std::cerr << "4-0" << std::endl;
  m_arpRequests.remove(entry);
  std::cerr << "4-1" << std::endl;
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{ std::cerr << "3-0" << std::endl;
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
   std::cerr << "3-1" << std::endl;
  auto entry = std::make_shared<ArpEntry>();
  std::cerr << "3-2" << std::endl;
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);
  std::cerr << "3-3" << std::endl;

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  //* remove request
  
  std::cerr << "3-4" << std::endl;
  if (request != m_arpRequests.end()) {
    std::cerr << "3-5" << std::endl;
    return *request;
  }
  else {
    std::cerr << "3-6" << std::endl;
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::recursive_mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::recursive_mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::recursive_mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
