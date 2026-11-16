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

#ifndef P4_TOPOLOGY_READER_HELPER_H
#define P4_TOPOLOGY_READER_HELPER_H

#include "ns3/p4-topology-reader.h"
#include <string>

namespace ns3 {

/**
 * \ingroup topology
 *
 * \brief Helper class to simplify the use of topology readers.
 *
 * This class allows users to set up and configure topology readers in a streamlined way.
 */
class P4TopologyReaderHelper
{
public:
  P4TopologyReaderHelper ();

  /**
   * \brief Sets the input file name.
   * \param [in] fileName The input file name.
   */
  void SetFileName (const std::string fileName);

  /**
   * \brief Sets the input file type. Supported file types include "P2P", and others.
   * \param [in] fileType The input file type.
   */
  void SetFileType (const std::string fileType);

  /**
   * \brief Returns a smart pointer to the configured TopologyReader.
   * \return The created TopologyReader object, or null if an error occurred.
   */
  Ptr<P4TopologyReader> GetTopologyReader ();

private:
  Ptr<P4TopologyReader> m_inputModel; //!< Smart pointer to the actual topology model.
  std::string m_fileName; //!< Name of the input file.
  std::string m_fileType; //!< Type of the input file.
};

} // namespace ns3

#endif /* P4_TOPOLOGY_READER_HELPER_H */