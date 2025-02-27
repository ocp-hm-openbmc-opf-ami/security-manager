/*
// Copyright (c) 2023 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <string>
#include <vector>

namespace security_manager
{

class FIPSInstaller
{
  public:
    FIPSInstaller(const FIPSInstaller&) = delete;
    FIPSInstaller& operator=(const FIPSInstaller&) = delete;
    FIPSInstaller(FIPSInstaller&&) = delete;
    FIPSInstaller& operator=(FIPSInstaller&&) = delete;

    FIPSInstaller(boost::asio::io_context& io,
                  std::shared_ptr<sdbusplus::asio::connection>& conn,
                  sdbusplus::asio::object_server& server);

  private:
    void registerFIPSProperties();
    void setFIPSStatus();
    bool installFIPSConfig();
    bool isValidVersion(std::string version);
    bool readOpenSSLConfig(std::string& readBuf);
    bool writeOpenSSLConfig(const std::string& writeBuf,
                            std::ios_base::openmode mode);
    bool enableFIPS(boost::asio::yield_context& yield, std::string version);
    bool disableFIPS(void);
    std::string getFIPSProviderInstalled();

    boost::asio::io_context& io;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    sdbusplus::asio::object_server& server;
    boost::asio::steady_timer pollTimer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> statusIntf;
    std::shared_ptr<sdbusplus::asio::dbus_interface> providerIntf;
    std::shared_ptr<sdbusplus::asio::dbus_interface> modeIntf;
    std::string fipsVersion = "na";
    const std::vector<std::string> availableProvider{"3.0.9"};
    static const inline std::chrono::seconds pollInterval{2};
}; // class FIPSInstaller

} // namespace security_manager
