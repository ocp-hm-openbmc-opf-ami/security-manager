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

#include "fips-installer.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace security_manager
{

const static constexpr char* fipsPath = "/com/intel/fips";
const static constexpr char* fipsStatusInferface =
    "com.intel.fips.status";
const static constexpr char* fipsProviderInterface =
    "com.intel.fips.providers";
const static constexpr char* fipsModeInterface =
    "com.intel.fips.mode";
const static constexpr char* opensslConfPath = "/etc/ssl/openssl.cnf";
const static constexpr char* fipsModuleConfPath = "/etc/ssl/fipsmodule.cnf";
const static constexpr char* fipsService =
    "com.intel.FipsConfigInstaller.service";

const std::string fipsConfig =
R"(#FIPS_CONFIG_START
.include /etc/ssl/fipsmodule.cnf
[openssl_init]
alg_section = algorithm_sect
[provider_sect]
fips = fips_sect
base = base_sect
[base_sect]
activate = 1
[algorithm_sect]
default_properties = fips = yes
#FIPS_CONFIG_END)";

FIPSInstaller::FIPSInstaller(
    boost::asio::io_context& ioService,
    std::shared_ptr<sdbusplus::asio::connection>& connection,
    sdbusplus::asio::object_server& srv) :
    io(ioService),
    conn(connection), server(srv), pollTimer(io)
{
    statusIntf = server.add_interface(fipsPath, fipsStatusInferface);
    providerIntf = server.add_interface(fipsPath, fipsProviderInterface);
    modeIntf = server.add_interface(fipsPath, fipsModeInterface);
    server.add_manager(fipsPath);
    registerFIPSProperties();
}

bool FIPSInstaller::installFIPSConfig()
{
    auto msg = conn->new_method_call(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "RestartUnit");
    msg.append(fipsService);
    msg.append("replace");
    try
    {
        auto reply = conn->call(msg);
        if (reply.is_method_error())
        {
            std::cerr << "Error Installing Fips Config \n";
            return false;
        }
        sdbusplus::message::object_path path;
        reply.read(path);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error Installing Fips Config:  \n" << e.what();
        return false;
    }
    return true;
}

void FIPSInstaller::registerFIPSProperties()
{
    if (!statusIntf->is_initialized())
    {
        fipsVersion = getFIPSProviderInstalled();
        bool enabled = !(fipsVersion == "na");
        statusIntf->register_property("Enabled", enabled);
        statusIntf->register_property("Version", fipsVersion);
        statusIntf->initialize(true);
    }

    if (!providerIntf->is_initialized())
    {
        providerIntf->register_property("AvailableProviders",
                                        availableProvider);
        providerIntf->initialize(true);
    }

    if (!modeIntf->is_initialized())
    {
        modeIntf->register_method(
            "EnableFips",
            [this](boost::asio::yield_context yield,
                   std::string& version) -> bool {
                std::cout << "Requested to install FIPS Version: \n" << version;
                return this->enableFIPS(yield, version);
            });
        modeIntf->register_method("DisableFips", [this](void) -> bool {
            return this->disableFIPS();
        });
        modeIntf->initialize(true);
    }
}

void FIPSInstaller::setFIPSStatus()
{
    statusIntf->set_property("Version", fipsVersion);
    bool enabled = !(fipsVersion == "na");
    statusIntf->set_property("Enabled", enabled);
}

bool FIPSInstaller::isValidVersion(std::string version)
{
    return std::find(availableProvider.cbegin(), availableProvider.cend(),
                     version) != availableProvider.cend();
}

bool FIPSInstaller::readOpenSSLConfig(std::string& readBuf)
{
    std::ifstream inFile(opensslConfPath);
    if (!inFile.is_open())
    {
        std::cerr << "Failed reading openssl.cnf \n";
        return false;
    }
    std::string str(std::istreambuf_iterator<char>{inFile}, {});
    while (!str.empty() && std::isspace(str.back()))
    {
        str.pop_back();
    }
    readBuf = str;
    inFile.close();
    return true;
}

bool FIPSInstaller::writeOpenSSLConfig(const std::string& writeBuf,
                                       std::ios_base::openmode mode)
{
    std::ofstream fp(opensslConfPath, mode);
    if (!fp.is_open())
    {
        return false;
    }
    fp << writeBuf;
    fp.close();
    return true;
}

bool FIPSInstaller::disableFIPS(void)
{
    std::string readBuf;
    if (fipsVersion == "na")
    {
        std::cerr << "FIPS is currently Disabled \n";
        return false;
    }
    if (!readOpenSSLConfig(readBuf))
    {
        std::cerr << "Failed reading openssl.cnf \n";
        return false;
    }
    auto eraseStart = readBuf.find("#FIPS_CONFIG_START");
    auto configLen = readBuf.length();
    readBuf.erase(eraseStart, configLen);

    if (!writeOpenSSLConfig(readBuf, std::ios::trunc))
    {
        return false;
    }
    if (!std::filesystem::remove(fipsModuleConfPath))
    {
        std::cerr << "Failed to remove fipsmodule.cnf \n";
        return false;
    }
    fipsVersion = "na";
    setFIPSStatus();
    return true;
}

bool FIPSInstaller::enableFIPS(boost::asio::yield_context& yield,
                               std::string version)
{
    boost::system::error_code ec;
    if (!isValidVersion(version))
    {
        std::cerr << "FIPS Provider Version is Invalid: \n" << version;
        return false;
    }
    if (version == fipsVersion)
    {
        return false;
    }
    if (!installFIPSConfig())
    {
        std::cerr << "Failed to install FIPS Config \n";
        return false;
    }
    pollTimer.expires_after(pollInterval);
    pollTimer.async_wait(yield[ec]);
    if (ec == boost::asio::error::operation_aborted)
    {
        std::cerr << "Failed to install FIPS Config \n";
        return false;
    }
    else if (ec)
    {
        std::cerr << "Failed to install FIPS Config \n";
        return false;
    }
    if (!std::filesystem::exists(fipsModuleConfPath))
    {
        std::cerr << "fipsmodule.cnf not found \n";
        return false;
    }
    if (!writeOpenSSLConfig(fipsConfig, std::ios::app))
    {
        std::cerr << "Failed to write to Config file \n";
        return false;
    }
    fipsVersion = version;
    setFIPSStatus();
    return true;
}

std::string FIPSInstaller::getFIPSProviderInstalled(void)
{
    /*TODO: Read Current Installed FIPS Provider via OpenSSL Provider module
        Currently, openssl.cnf file is parsed to check for the presence of
       fipsConfig and based on that provider installed is returned
    */
    std::string readBuf;
    if (!std::filesystem::exists(fipsModuleConfPath))
    {
        return "na";
    }
    if (!readOpenSSLConfig(readBuf))
    {
        std::cerr << "Failed reading openssl.cnf \n";
        return "na";
    }
    bool isFound = readBuf.find(fipsConfig) != std::string::npos;
    if (isFound)
    {
        return "3.0.9";
    }
    return "na";
}

} // namespace security_manager
