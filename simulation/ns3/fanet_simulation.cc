// Starter NS-3 scratch program for AEX-TFANET.
// Requires a configured NS-3 tree with core, network, internet, wifi, mobility,
// applications and flow-monitor modules. This source has not been compiled here.
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"

#include <fstream>
#include <string>

using namespace ns3;

int main(int argc, char** argv) {
  uint32_t nUavs = 10;
  double duration = 100.0;
  uint32_t seed = 42;
  std::string output = "fanet_flow_stats.xml";
  CommandLine cmd(__FILE__);
  cmd.AddValue("nUavs", "Number of UAV nodes", nUavs);
  cmd.AddValue("duration", "Simulation duration in seconds", duration);
  cmd.AddValue("seed", "Deterministic RNG seed", seed);
  cmd.AddValue("output", "FlowMonitor XML output", output);
  cmd.Parse(argc, argv);
  RngSeedManager::SetSeed(seed);
  RngSeedManager::SetRun(1);

  NodeContainer nodes;
  nodes.Create(nUavs);
  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());
  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211b);
  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::RandomRectanglePositionAllocator",
      "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=500]"),
      "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=500]"));
  mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
      "Speed", StringValue("ns3::UniformRandomVariable[Min=5|Max=20]"),
      "Pause", StringValue("ns3::ConstantRandomVariable[Constant=1]"),
      "PositionAllocator", PointerValue(CreateObject<RandomRectanglePositionAllocator>()));
  mobility.Install(nodes);

  InternetStackHelper internet;
  internet.Install(nodes);
  Ipv4AddressHelper addresses;
  addresses.SetBase("10.1.0.0", "255.255.0.0");
  Ipv4InterfaceContainer interfaces = addresses.Assign(devices);
  UdpEchoServerHelper server(9);
  ApplicationContainer serverApps = server.Install(nodes.Get(nUavs - 1));
  serverApps.Start(Seconds(1.0));
  serverApps.Stop(Seconds(duration));
  UdpEchoClientHelper client(interfaces.GetAddress(nUavs - 1), 9);
  client.SetAttribute("MaxPackets", UintegerValue(100000));
  client.SetAttribute("Interval", TimeValue(Seconds(1.0)));
  client.SetAttribute("PacketSize", UintegerValue(512));
  ApplicationContainer clients = client.Install(nodes.Get(0));
  clients.Start(Seconds(2.0));
  clients.Stop(Seconds(duration));

  FlowMonitorHelper flowHelper;
  Ptr<FlowMonitor> monitor = flowHelper.InstallAll();
  Simulator::Stop(Seconds(duration));
  Simulator::Run();
  monitor->SerializeToXmlFile(output, true, true);
  Simulator::Destroy();
  return 0;
}
