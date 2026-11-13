/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Tommaso Pecorella (tommaso.pecorella@unifi.it)
 * Author: Valerio Sartini (valesar@gmail.com)
 */

#include "ns3/p4-topology-reader-helper.h"
#include "ns3/p4-topology-reader.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("P4TopologyReaderHelper");

P4TopologyReaderHelper::P4TopologyReaderHelper ()
    : m_inputModel (nullptr), m_fileName (""), m_fileType ("")
{
  NS_LOG_FUNCTION (this);
}

void
P4TopologyReaderHelper::SetFileName (const std::string fileName)
{
  NS_LOG_FUNCTION (this << fileName);
  m_fileName = fileName;
}

void
P4TopologyReaderHelper::SetFileType (const std::string fileType)
{
  NS_LOG_FUNCTION (this << fileType);
  m_fileType = fileType;
}

Ptr<P4TopologyReader>
P4TopologyReaderHelper::GetTopologyReader ()
{
  NS_LOG_FUNCTION (this);

  if (!m_inputModel)
    {
      if (m_fileType.empty ())
        {
          NS_LOG_ERROR ("File type is not set. Use SetFileType to specify a valid topology type.");
          return nullptr;
        }

      if (m_fileName.empty ())
        {
          NS_LOG_ERROR ("File name is not set. Use SetFileName to specify the input file.");
          return nullptr;
        }

      NS_LOG_INFO ("Creating a P2P formatted topology reader.");
      m_inputModel = CreateObject<P4TopologyReader> ();

      NS_LOG_INFO ("Setting file name to " << m_fileName);
      m_inputModel->SetFileName (m_fileName);

      if (!m_inputModel->Read ())
        {
          NS_LOG_ERROR ("Failed to read the topology file.");
          return nullptr;
        }
    }

  return m_inputModel;
}

} // namespace ns3
