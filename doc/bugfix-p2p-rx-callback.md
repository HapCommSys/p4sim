# Bug Fix: P2P Rx Callback Silent Drop (PacketSink Receives 0 Bytes)

**Date:** 2026-02-22  
**Author:** Mingyu Ma \<mingyu.ma@tu-dresden.de\>  
**Affected files:**
- `model/p4-switch-net-device.cc`
- `model/custom-p2p-net-device.cc`

---

## Symptom

When running `p4-basic-tunnel` (or any P4 example that uses `P4PointToPointHelper`
with `CustomP2PNetDevice` on end-hosts), the `PacketSink` application receives
**zero bytes** even though PCAP traces confirm packets arrive at the destination
link:

```
======================================
  Final Simulation Results
======================================
  Tx window : 3.002 s  ->  5.998 s  (2.996 s)
  Rx window : 0 s  ->  0 s  (0 s)
  Flow 1 (tunnel) Tx : 374000 bytes
  Flow 1 (tunnel) Rx : 0 bytes
  Flow 2 (normal) Tx : 1499000 bytes
  Flow 2 (normal) Rx : 0 bytes
  Total Rx : 0 bytes
  Rx goodput: N/A (measurement window is zero)
======================================
```

The `Rx` trace source on `PacketSink` is never called because `m_rxCallback`
inside `CustomP2PNetDevice::Receive()` is invoked with `protocol = 0`, causing
the NS-3 IP stack to silently drop every arriving packet.

---

## Root Cause Analysis

The receive path for a P2P-channel P4 switch topology is:

```
Host[0] (src)
  └─ CustomP2PNetDevice::SendFrom()       ← adds Ethernet + custom tunnel header
       └─ [wire: Eth(0xDC)+myTunnel+IPv4+UDP+payload]
Switch[0] port device
  └─ CustomP2PNetDevice::ProcessHeader()  ← strips Ethernet, param = 0xDC
       └─ P4SwitchNetDevice::ReceiveFromDevice()
            └─ bmv2 P4 pipeline (tunnel forwarding)
            └─ SendNs3Packet()            ← strips P4-Ethernet, calls Send(proto=0xDC)
Switch[1] port device
  └─ CustomP2PNetDevice::SendFrom()       ← re-wraps with Ethernet(0xDC)
  └─ CustomP2PNetDevice::ProcessHeader()  ← strips Ethernet, param = 0xDC
       └─ P4SwitchNetDevice::ReceiveFromDevice()
            └─ bmv2 P4 pipeline (tunnel forwarding to host port)
            └─ SendNs3Packet()            ← strips P4-Ethernet, calls Send(proto=0xDC)
Host[1] port device (switch side)
  └─ CustomP2PNetDevice::SendFrom()       ← re-wraps with Ethernet(0xDC)
Host[1] (dst)
  └─ CustomP2PNetDevice::Receive()
       └─ ProcessHeader()                 ← BUG: param ends up 0 → IP stack drops
```

### Bug 1 — `P4SwitchNetDevice::ReceiveFromDevice` (P4CHANNELP2P branch)

**File:** `model/p4-switch-net-device.cc`

The `P4CHANNELP2P` branch attempted to recover the Ethernet header from the
packet bytes using `PeekHeader(eeh_1)`:

```cpp
// OLD (broken)
EthernetHeader eeh_1;
if (ns3Packet->PeekHeader(eeh_1)) {
    ns3Packet->RemoveHeader(eeh_1);   // ← consumes first 14 bytes
} else {
    eeh_1.SetLengthType(protocol);
}
eeh_1.SetDestination(dst48);
eeh_1.SetSource(src48);
// EtherType NOT reset — keeps whatever PeekHeader read
ns3Packet->AddHeader(eeh_1);
```

**Why it fails:**  
`CustomP2PNetDevice::ProcessHeader()` had already stripped the real Ethernet
header before delivering the packet to the node's protocol handler. So the
packet entering `ReceiveFromDevice` is raw payload bytes (`[IPv4]` or
`[myTunnel][IPv4]`), **not** an Ethernet frame.

NS-3's `EthernetHeader::Deserialize()` always "succeeds" on any packet ≥ 14
bytes — it blindly reads 14 bytes with no validity check. Therefore
`PeekHeader(eeh_1)` returned `true` and consumed the first 14 bytes of the
**IPv4 header**, producing a garbage EtherType such as `0xa01` (bytes 12–13
of a `10.1.x.x` source address) or `0x4011` (TTL=64, protocol=17).

This garbage EtherType propagated through all subsequent switches and was
ultimately passed as `protocol` to `m_rxCallback` on the destination host,
where `0xa01` caused the IP stack to drop the packet.

---

### Bug 2 — `CustomP2PNetDevice::ProcessHeader()` (post-`RestoreHeaders` path)

**File:** `model/custom-p2p-net-device.cc`

After `RestoreHeaders()` completed, the code tried to strip a final Ethernet
header:

```cpp
// OLD (broken)
EthernetHeader eth;
if (p->PeekHeader(eth))
{
    param = eth.GetLengthType();
    p->RemoveHeader(eth);
}
else
{
    NS_LOG_WARN("ProcessHeader: no Ethernet header found");
}
```

**Why it fails:**  
`RestoreHeaders()` correctly strips the incoming Ethernet wrapper and rebuilds
the inner headers (IPv4 + UDP/TCP), but it does **not** re-add the Ethernet
header (the `case 0x1` in the reverse-parse loop is a no-op). The packet after
`RestoreHeaders()` is therefore `[IPv4][UDP][payload]` — no Ethernet.

The subsequent `PeekHeader(EthernetHeader)` on this bare packet again
"succeeded" by misreading the IPv4 header bytes as Ethernet, producing
`param = 0` (or another garbage value). With `param = 0`, the NS-3 IP stack
in `m_rxCallback` dropped every packet.

#### Secondary sub-bug in `RestoreHeaders` / `CheckIfCustomHeader`

`HandleLayer3(ADD_BEFORE)` calls `cus_hd.SetProtocolFieldNumber(0x0800)`,
intending to say "the next protocol after the custom header is IPv4 (0x0800)".
However, `SetProtocolFieldNumber(id)` treats `id` as a **field index**, not a
protocol value. With only 2 fields (indices 0 and 1), an index of `0x0800 = 2048`
is out of bounds and `GetProtocolNumber()` returns **0**. As a result,
`CheckIfCustomHeader()` always returns 0 for the `LAYER_3+ADD_BEFORE` case,
meaning the tunnel custom header is stripped but its "next protocol" field is
not read — the while loop exits early and the packet is partially parsed.
(The immediate fix for the Rx path does not require correcting this sub-bug
because the outer Ethernet EtherType is now used directly; see Bug 1 fix.)

---

## Fix

### Fix 1 — `model/p4-switch-net-device.cc`

Replace the `PeekHeader`-based Ethernet reconstruction with a clean rebuild
from the metadata parameters that are already passed to `ReceiveFromDevice`.
These parameters come directly from `CustomP2PNetDevice::ProcessHeader()`,
which correctly extracted the real EtherType from the wire-level Ethernet frame.

```cpp
// NEW (correct)
} else if (m_channelType == P4CHANNELP2P) {
    // Build the Ethernet header the P4 parser expects from the metadata
    // passed by the port device — NOT by peeking packet bytes (which are
    // not an Ethernet frame at this point).
    EthernetHeader eeh_1;
    eeh_1.SetDestination(dst48);
    eeh_1.SetSource(src48);
    eeh_1.SetLengthType(protocol);   // ← EtherType from the stripped wire header
    ns3Packet->AddHeader(eeh_1);
```

**Why this is correct:**  
`protocol` is set by `CustomP2PNetDevice::ProcessHeader()` from
`eth.GetLengthType()` of the real Ethernet header that was on the wire. It
carries exactly the EtherType the P4 program needs (`0x0800` for plain IPv4,
`0x0DC` for a tunnelled packet). No packet bytes are consumed.

---

### Fix 2 — `model/custom-p2p-net-device.cc`

After `RestoreHeaders()`, detect the inner protocol by peeking `Ipv4Header` or
`ArpHeader` directly — never `EthernetHeader`, because the Ethernet has already
been consumed by `RestoreHeaders()`.

```cpp
// NEW (correct)
if (m_NeedProcessHeader)
{
    RestoreHeaders(p);   // packet is now [IPv4|ARP][...] — no Ethernet

    Ipv4Header ipv4Peek;
    ArpHeader  arpPeek;
    if (p->PeekHeader(ipv4Peek))
        param = 0x0800;          // IPv4
    else if (p->PeekHeader(arpPeek))
        param = 0x0806;          // ARP
    else
        NS_LOG_WARN("cannot determine protocol after RestoreHeaders");
    return true;
}

// m_NeedProcessHeader == false (switch ports): Ethernet wrapper IS present.
EthernetHeader eth;
if (p->PeekHeader(eth)) {
    param = eth.GetLengthType();
    p->RemoveHeader(eth);
}
```

`Ipv4Header::Deserialize()` validates the version/IHL nibble (must be 4 / ≥ 5),
so it correctly rejects non-IPv4 data. This makes the detection robust.

---

## Verification

After applying both fixes, `p4-basic-tunnel` produces 100 % packet delivery for
both the tunnelled flow (port 12000) and the plain IPv4 flow (port 1301):

```
======================================
  Final Simulation Results
======================================
  Tx window : 3.002 s  ->  5.998 s  (2.996 s)
  Rx window : 3.012 s  ->  6.005 s  (2.993 s)
  Flow 1 (tunnel) Tx : 374000 bytes
  Flow 1 (tunnel) Rx : 374000 bytes     ← was 0
  Flow 2 (normal) Tx : 1499000 bytes
  Flow 2 (normal) Rx : 1499000 bytes    ← was 0
  Total Tx : 1873000 bytes
  Total Rx : 1873000 bytes
  Tx goodput: 5.001 Mbps
  Rx goodput: 5.006 Mbps
======================================
```

---

## Affected Examples

Any NS-3/P4sim example that uses **`P4PointToPointHelper`** (i.e. `ChannelType=1`)
with at least one `CustomP2PNetDevice` host is affected by these bugs. Examples
include:

| Example file | Uses P2P channel | Custom header |
|---|---|---|
| `p4-basic-tunnel.cc` | ✓ | ✓ tunnel header |
| `p4-v1model-ipv4-forwarding.cc` | ✓ | — |
| `p4-psa-ipv4-forwarding.cc` | ✓ | — |
| `p4-l3-router.cc` | ✓ | — |
| `p4-firewall.cc` | ✓ | — |
| `p4-custom-header-test.cc` | ✓ | ✓ |
| `p4-p2p-custom-header-test.cc` | ✓ | ✓ |

---

## Notes

- The CSMA channel path (`P4CHANNELCSMA`, `ChannelType=0`) is **not affected**
  because it always reconstructs the Ethernet header from metadata (no
  `PeekHeader` involved).
- The `SetProtocolFieldNumber` / field-index confusion noted above is a latent
  bug; it does not affect tunnel correctness once Bug 1 is fixed (the EtherType
  from the outer Ethernet frame carries the correct `0xDC` type through the
  pipeline), but it means `GetProtocolNumber()` always returns 0 for
  `LAYER_3+ADD_BEFORE` custom headers, which may matter for future features.
