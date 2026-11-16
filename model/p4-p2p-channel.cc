#include "ns3/log.h"
#include "ns3/p4-p2p-channel.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/trace-source-accessor.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("P4P2PChannel");

NS_OBJECT_ENSURE_REGISTERED(P4P2PChannel);

TypeId
P4P2PChannel::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::P4P2PChannel")
            .SetParent<Channel>()
            .SetGroupName("PointToPoint")
            .AddConstructor<P4P2PChannel>()
            .AddAttribute("Delay",
                          "Propagation delay through the channel",
                          TimeValue(Seconds(0)),
                          MakeTimeAccessor(&P4P2PChannel::m_delay),
                          MakeTimeChecker())
            .AddTraceSource("TxRxPointToPoint",
                            "Trace source indicating transmission of packet "
                            "from the P4P2PChannel, used by the Animation "
                            "interface.",
                            MakeTraceSourceAccessor(&P4P2PChannel::m_txrxPointToPoint),
                            "ns3::P4P2PChannel::TxRxAnimationCallback");
    return tid;
}

P4P2PChannel::P4P2PChannel()
    : Channel(),
      m_delay(Seconds(0.)),
      m_nDevices(0)
{
    NS_LOG_INFO("P4P2PChannel created.");
}

P4P2PChannel::~P4P2PChannel()
{
    NS_LOG_INFO("P4P2PChannel destroyed.");
}

void
P4P2PChannel::Attach(Ptr<CustomP2PNetDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    NS_ASSERT_MSG(m_nDevices < N_DEVICES, "Only two devices permitted");
    NS_ASSERT(device != nullptr);

    m_link[m_nDevices++].m_src = device;
    //
    // If we have both devices connected to the channel, then finish introducing
    // the two halves and set the links to IDLE.
    //
    if (m_nDevices == N_DEVICES)
    {
        m_link[0].m_dst = m_link[1].m_src;
        m_link[1].m_dst = m_link[0].m_src;
        m_link[0].m_state = IDLE;
        m_link[1].m_state = IDLE;
    }
}

bool
P4P2PChannel::TransmitStart(Ptr<const Packet> p, Ptr<CustomP2PNetDevice> src, Time txTime)
{
    NS_LOG_FUNCTION(this << p << src);
    NS_LOG_LOGIC("UID is " << p->GetUid() << ")");

    NS_ASSERT(m_link[0].m_state != INITIALIZING);
    NS_ASSERT(m_link[1].m_state != INITIALIZING);

    uint32_t wire = src == m_link[0].m_src ? 0 : 1;

    Simulator::ScheduleWithContext(m_link[wire].m_dst->GetNode()->GetId(),
                                   txTime + m_delay,
                                   &CustomP2PNetDevice::Receive,
                                   m_link[wire].m_dst,
                                   p->Copy());

    // Call the tx anim callback on the net device
    m_txrxPointToPoint(p, src, m_link[wire].m_dst, txTime, txTime + m_delay);
    return true;
}

std::size_t
P4P2PChannel::GetNDevices(void) const
{
    NS_LOG_FUNCTION_NOARGS();
    return m_nDevices;
}

Ptr<CustomP2PNetDevice>
P4P2PChannel::GetPointToPointDevice(std::size_t i) const
{
    NS_LOG_FUNCTION_NOARGS();
    NS_ASSERT(i < 2);
    return m_link[i].m_src;
}

Ptr<NetDevice>
P4P2PChannel::GetDevice(std::size_t i) const
{
    NS_LOG_FUNCTION_NOARGS();
    return GetPointToPointDevice(i);
}

Time
P4P2PChannel::GetDelay(void) const
{
    return m_delay;
}

Ptr<CustomP2PNetDevice>
P4P2PChannel::GetSource(uint32_t i) const
{
    return m_link[i].m_src;
}

Ptr<CustomP2PNetDevice>
P4P2PChannel::GetDestination(uint32_t i) const
{
    return m_link[i].m_dst;
}

bool
P4P2PChannel::IsInitialized(void) const
{
    NS_ASSERT(m_link[0].m_state != INITIALIZING);
    NS_ASSERT(m_link[1].m_state != INITIALIZING);
    return true;
}

} // namespace ns3
